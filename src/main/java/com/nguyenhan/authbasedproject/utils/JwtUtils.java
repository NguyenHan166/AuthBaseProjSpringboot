package com.nguyenhan.authbasedproject.utils;

import com.nguyenhan.authbasedproject.entity.User;
import com.nguyenhan.authbasedproject.service.auth.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.UUID;


@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration}")
    private int jwtExpirationMs;

    @Value("${app.jwt.refresh-expiration}")
    private int refreshTokenExpirationMs;

    public String generateJwtToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder()
                .subject((userPrincipal.getUsername()))
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .claim("type", "access")
                .claim("userId", userPrincipal.getId())
                .signWith(key())
                .compact();
    }

    public String generateTokenFromUser(User user){
//        UserDetailsImpl userPrincipal = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
//        if (userPrincipal == null || !userPrincipal.getUsername().equals(username)) {
//            throw new IllegalArgumentException("User not authenticated or username does not match");
//        }
        return Jwts.builder()
                .subject(user.getUsername())
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .claim("type", "access")
                .claim("userId", user.getId()) // Assuming userId is not available here
                .signWith(key())
                .compact();
    }

    public String generateRefreshToken(String username, Long userId) {
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + refreshTokenExpirationMs))
                .claim("type", "refresh")
                .claim("userId", userId)
                .claim("jti" , UUID.randomUUID().toString()) // unique token ID
                .signWith(key())
                .compact();
    }

    private Key key() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        // Ensure the key is at least 256 bits (32 bytes)
        if (keyBytes.length < 32) {
            throw new IllegalArgumentException("JWT secret key must be at least 256 bits (32 bytes) long");
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public Long getUserIdFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("userId", Long.class);
    }

    public String getTokenTypeFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("type", String.class);
    }

    public String getJwtIdFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("jti", String.class);
    }

    public boolean validateJwtAccessToken(String authToken) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build()
                    .parseSignedClaims(authToken)
                    .getPayload();

            String tokenType = claims.get("type", String.class);
            if (!"access".equals(tokenType)) {
                logger.error("Invalid token type: {}", tokenType);
                return false;
            }
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }

    public boolean validateRefreshToken(String refreshToken) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build()
                    .parseSignedClaims(refreshToken)
                    .getPayload();

            String tokenType = claims.get("type", String.class);
            if (!"refresh".equals(tokenType)) {
                logger.error("Invalid token type: {}", tokenType);
                return false;
            }
            return true;

        }catch (Exception e) {
            logger.error("Invalid refresh token: {}", e.getMessage());
            return false;
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            Date expiration = claims.getExpiration();
            return expiration.before(new Date());
        } catch (Exception e) {
            logger.error("Error checking token expiration: {}", e.getMessage());
            return true;
        }
    }


}

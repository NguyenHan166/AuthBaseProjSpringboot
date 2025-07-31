package com.nguyenhan.authbasedproject.service.auth;

import com.nguyenhan.authbasedproject.entity.RefreshToken;
import com.nguyenhan.authbasedproject.entity.User;
import com.nguyenhan.authbasedproject.exception.TokenRefreshException;
import com.nguyenhan.authbasedproject.repository.RefreshTokenRepository;
import com.nguyenhan.authbasedproject.repository.UserRepository;
import com.nguyenhan.authbasedproject.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Value("${app.jwt.refresh-expiration}")
    private Long refreshTokenDurationMs;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtils jwtUtils;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public RefreshToken createRefreshToken(Long userId) {

        User user = userRepository.findById(userId).orElseThrow(
                () -> new RuntimeException("User not found with id: " + userId)
        );


        RefreshToken refreshToken = refreshTokenRepository.findByUser(user).orElse(new RefreshToken());
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));

        String jwtRefreshToken = jwtUtils.generateRefreshToken(user.getUsername(), user.getId());
        refreshToken.setToken(jwtRefreshToken);

        refreshToken = refreshTokenRepository.save(refreshToken);

        return refreshToken;
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token was expired. Please make a new sign-in request");
        }
        return token;
    }

    @Transactional
    public RefreshToken processRefreshToken(String requestRefreshToken) {
        // check validate jwt token
        if (!jwtUtils.validateRefreshToken(requestRefreshToken)) {
            throw new TokenRefreshException( requestRefreshToken , "Invalid refresh token");
        }

        // check expiration
        if (jwtUtils.isTokenExpired(requestRefreshToken)) {
            throw new TokenRefreshException(requestRefreshToken, "Refresh token is expired");
        }

        // Find the refresh token in the database
        RefreshToken refreshTokenEntity = findByToken(requestRefreshToken).orElseThrow(
                () -> new TokenRefreshException(requestRefreshToken, "Refresh token not found in database")
        );

        // Verify the expiration date in db
        verifyExpiration(refreshTokenEntity);

        // security check - token reuse detection
        if (refreshTokenEntity.isTokenUsed(requestRefreshToken)){
            deleteByUserId(refreshTokenEntity.getUser().getId());
            throw new TokenRefreshException(requestRefreshToken,
                    "Refresh token reuse detected. All tokens have been revoked. Please login again.");
        }

        refreshTokenEntity.addUsedToken(requestRefreshToken);
        refreshTokenRepository.save(refreshTokenEntity);

        // Generate a new refresh token
        User user = refreshTokenEntity.getUser();
        String newRefreshToken = jwtUtils.generateRefreshToken(user.getUsername(), user.getId());

        refreshTokenEntity.setToken(newRefreshToken);
        refreshTokenEntity.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));

        return refreshTokenRepository.save(refreshTokenEntity);
    }

    public boolean isRefreshTokenValid(String token) {
        try {
            // JWT format validation
            if (!jwtUtils.validateRefreshToken(token)) return false;

            // Expiration check
            if (jwtUtils.isTokenExpired(token)) return false;

            // Database existence check
            Optional<RefreshToken> refreshTokenOpt = findByToken(token);
            if (refreshTokenOpt.isEmpty()) return false;

            RefreshToken refreshToken = refreshTokenOpt.get();

            // Database expiration check
            if (refreshToken.getExpiryDate().compareTo(Instant.now()) < 0) return false;

            // 🔐 Token reuse check
            return !refreshToken.isTokenUsed(token);

        } catch (Exception e) {
            return false;
        }
    }



    @Transactional
    public int deleteByUserId(Long userId) {
        return refreshTokenRepository.deleteByUser(userRepository.findById(userId).get());
    }

}

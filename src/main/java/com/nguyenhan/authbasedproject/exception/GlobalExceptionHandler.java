package com.nguyenhan.authbasedproject.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // 🚨 Handle token refresh security violations
    @ExceptionHandler(TokenRefreshException.class)
    public ResponseEntity<Map<String, Object>> handleTokenRefreshException(TokenRefreshException ex) {
        logger.warn("Token refresh error: {}", ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.FORBIDDEN.value());
        response.put("error", "Token Refresh Error");
        response.put("message", ex.getMessage());

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    // 🚨 Handle token reuse detection (CRITICAL SECURITY)
    @ExceptionHandler(TokenRefreshReuseException.class)
    public ResponseEntity<Map<String, Object>> handleRefreshTokenReuseException(TokenRefreshReuseException ex) {
        logger.error("SECURITY ALERT - Refresh token reuse detected: {}", ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.FORBIDDEN.value());
        response.put("error", "Security Violation");
        response.put("message", "Token reuse detected. Please login again.");

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    // 🚨 Handle token expiration (CRITICAL SECURITY)
    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<Map<String, Object>> handleTokenExpiredException(TokenExpiredException ex) {
        logger.warn("Token expired: {}", ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.UNAUTHORIZED.value());
        response.put("error", "Token Expired");
        response.put("message", ex.getMessage());

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }
}

package com.nguyenhan.authbasedproject.exception;

public class TokenRefreshReuseException extends RuntimeException{
    private static final long serialVersionUID = 1L;

    public TokenRefreshReuseException(String token, String message) {
        super(String.format("Failed for Token [%s]: %s", token, message));
    }
}

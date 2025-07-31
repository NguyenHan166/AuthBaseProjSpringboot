package com.nguyenhan.authbasedproject.exception;

public class TokenExpiredException extends RuntimeException{
    private static final long serialVersionUID = 1L;

    public TokenExpiredException(String token, String message) {
        super(String.format("Token [%s] is expired: %s", token, message));
    }
}

package com.nguyenhan.authbasedproject.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    /**
     * This method is called when an unauthenticated user tries to access a protected resource.
     * It can be used to send an error response or redirect the user to a login page.
     *
     * @param request  the HTTP request
     * @param response the HTTP response
     * @param authException the authentication exception that occurred
     * @throws IOException if an I/O error occurs
     * @throws ServletException if a servlet error occurs
     */

    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        logger.error("Unauthorized error: {}", authException.getMessage());

        String errorCode = (String) request.getAttribute("exception");

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        Map<String, Object> body = new HashMap<>();
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("path", request.getServletPath());

        switch (errorCode) {
            case "TokenExpired" -> {
                body.put("error", "TokenExpired");
                body.put("message", "Access token has expired");
            }
            case "InvalidToken" -> {
                body.put("error", "InvalidToken");
                body.put("message", "Invalid JWT token");
            }
            default -> {
                body.put("error", "Unauthorized");
                body.put("message", authException.getMessage());
            }
        }

        new ObjectMapper().writeValue(response.getOutputStream(), body);
    }
}

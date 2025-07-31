package com.nguyenhan.authbasedproject.controller;

import com.nguyenhan.authbasedproject.constant.role.ERole;
import com.nguyenhan.authbasedproject.dto.request.LoginRequest;
import com.nguyenhan.authbasedproject.dto.request.SignupRequest;
import com.nguyenhan.authbasedproject.dto.request.TokenRefreshRequest;
import com.nguyenhan.authbasedproject.dto.response.JwtResponse;
import com.nguyenhan.authbasedproject.dto.response.MessageResponse;
import com.nguyenhan.authbasedproject.dto.response.TokenRefreshResponse;
import com.nguyenhan.authbasedproject.entity.RefreshToken;
import com.nguyenhan.authbasedproject.entity.Role;
import com.nguyenhan.authbasedproject.entity.User;
import com.nguyenhan.authbasedproject.exception.TokenRefreshException;
import com.nguyenhan.authbasedproject.repository.RoleRepository;
import com.nguyenhan.authbasedproject.repository.UserRepository;
import com.nguyenhan.authbasedproject.service.auth.RefreshTokenService;
import com.nguyenhan.authbasedproject.service.auth.UserDetailsImpl;
import com.nguyenhan.authbasedproject.utils.JwtUtils;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    RefreshTokenService refreshTokenService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    private final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        return ResponseEntity.ok(new JwtResponse(jwt,
                refreshToken.getToken(),
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles
                ));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        User user = new User(signupRequest.getUsername(), signupRequest.getEmail(), passwordEncoder.encode(signupRequest.getPassword()));
        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(
                    () -> new RuntimeException("Error: Role is not found.")
            );
            roles.add(userRole);
        }else{
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN).orElseThrow(
                                () -> new RuntimeException("Error: Role is not found.")
                        );
                        roles.add(adminRole);
                        break;
                    case "employee":
                        Role empRole = roleRepository.findByName(ERole.ROLE_EMPLOYEE).orElseThrow(
                                () -> new RuntimeException("Error: Role is not found.")
                        );
                        roles.add(empRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(
                                () -> new RuntimeException("Error: Role is not found.")
                        );
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        try{
            RefreshToken refreshToken = refreshTokenService.processRefreshToken(requestRefreshToken);

            User user = refreshToken.getUser();
            String newAccessToken = jwtUtils.generateTokenFromUser(user);
            String newRefreshToken = refreshTokenService.createRefreshToken(user.getId()).getToken();

            return ResponseEntity.ok(new TokenRefreshResponse(newAccessToken, refreshToken.getToken()));
        }catch (TokenRefreshException e) {
            logger.warn("Token refresh failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new MessageResponse(e.getMessage()));
        }catch (Exception e) {
            logger.error("Unexpected error during token refresh: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new MessageResponse("An unexpected error occurred while refreshing the token."));
        }
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser() {
        try{
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !(authentication.getPrincipal() instanceof UserDetailsImpl)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("User is not authenticated."));
            }
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            Long userId = userDetails.getId();

            refreshTokenService.deleteByUserId(userId);

            logger.info("User logged out successfully");
            return ResponseEntity.ok(new MessageResponse("User logged out successfully!"));
        }catch (Exception e) {
            logger.error("Unexpected error during logout: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new MessageResponse("An unexpected error occurred while logging out."));
        }
    }

    // Security endpoint: Revoke all tokens
    @PostMapping("/revoke-all-tokens")
    public ResponseEntity<?> revokeAllTokens() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            Long userId = userDetails.getId();

            refreshTokenService.deleteByUserId(userId);

            logger.info("All tokens revoked for user {}", userDetails.getUsername());
            return ResponseEntity.ok(new MessageResponse("All refresh tokens have been revoked successfully!"));
        } catch (Exception e) {
            logger.error("Error revoking tokens: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Error revoking tokens"));
        }
    }

    // Validation endpoint
    @GetMapping("/validate-refresh-token")
    public ResponseEntity<?> validateRefreshToken(@RequestParam String refreshToken) {
        try {
            boolean isValid = refreshTokenService.isRefreshTokenValid(refreshToken);
            if (isValid) {
                return ResponseEntity.ok(new MessageResponse("Refresh token is valid"));
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new MessageResponse("Refresh token is invalid or expired"));
            }
        } catch (Exception e) {
            logger.error("Error validating refresh token: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Error validating refresh token"));
        }
    }

}

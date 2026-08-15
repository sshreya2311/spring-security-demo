package com.example.securitydemo;

import com.example.securitydemo.jwt.JwtUtils;
import com.example.securitydemo.jwt.LoginRequest;
import com.example.securitydemo.jwt.LoginResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class GreetingController {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    // Public endpoint
    @GetMapping("/hello")
    public String sayHello() {
        return "Hello";
    }

    // USER role required
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userEndpoint() {
        return "Hello, User!";
    }

    // ADMIN role required
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint() {
        return "Hello, Admin!";
    }

    // Login endpoint
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(
            @RequestBody LoginRequest loginRequest) {

        Authentication authentication;

        try {

            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

        } catch (AuthenticationException exception) {

            Map<String, Object> map = new HashMap<>();

            map.put("message", "Bad credentials");
            map.put("status", false);

            return new ResponseEntity<>(
                    map,
                    HttpStatus.UNAUTHORIZED
            );
        }

        // Set authenticated user
        SecurityContextHolder
                .getContext()
                .setAuthentication(authentication);

        // Get authenticated user's details
        UserDetails userDetails =
                (UserDetails) authentication.getPrincipal();

        // Generate JWT
        String jwtToken =
                jwtUtils.generateTokenFromUsername(userDetails);

        // Get user's roles
        List<String> roles =
                userDetails.getAuthorities()
                        .stream()
                        .map(item -> item.getAuthority())
                        .collect(Collectors.toList());

        // Create login response
        LoginResponse response =
                new LoginResponse(
                        jwtToken,
                        userDetails.getUsername(),
                        roles
                );

        return ResponseEntity.ok(response);
    }
}
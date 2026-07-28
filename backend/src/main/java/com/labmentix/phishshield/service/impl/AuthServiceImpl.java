package com.labmentix.phishshield.service.impl;

import com.labmentix.phishshield.dto.AuthResponse;
import com.labmentix.phishshield.dto.LoginRequest;
import com.labmentix.phishshield.dto.RegisterRequest;
import com.labmentix.phishshield.entity.User;
import com.labmentix.phishshield.enums.Role;
import com.labmentix.phishshield.exception.DuplicateResourceException;
import com.labmentix.phishshield.repository.UserRepository;
import com.labmentix.phishshield.security.AppUserPrincipal;
import com.labmentix.phishshield.security.JwtService;
import com.labmentix.phishshield.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new DuplicateResourceException("An account with this email already exists");
        }

        User user = User.builder()
                .name(request.name())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(Role.USER)
                .enabled(true)
                .build();

        User saved = userRepository.save(user);
        return issueToken(saved);
    }

    @Override
    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
        );

        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found - this should not happen"));

        return issueToken(user);
    }

    private AuthResponse issueToken(User user) {
        AppUserPrincipal principal = new AppUserPrincipal(user);
        String token = jwtService.generateToken(principal, Map.of(
                "role", user.getRole().name(),
                "name", user.getName()
        ));

        return AuthResponse.builder()
                .accessToken(token)
                .tokenType("Bearer")
                .name(user.getName())
                .email(user.getEmail())
                .role(user.getRole().name())
                .build();
    }
}

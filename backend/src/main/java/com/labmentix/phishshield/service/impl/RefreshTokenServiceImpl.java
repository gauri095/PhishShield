package com.labmentix.phishshield.service.impl;

import com.labmentix.phishshield.entity.RefreshToken;
import com.labmentix.phishshield.entity.User;
import com.labmentix.phishshield.exception.InvalidRefreshTokenException;
import com.labmentix.phishshield.repository.RefreshTokenRepository;
import com.labmentix.phishshield.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${app.jwt.refresh-token-expiration-ms}")
    private long refreshTokenExpirationMs;

    @Override
    @Transactional
    public String issue(User user) {
        String rawToken = generateRawToken();

        RefreshToken entity = RefreshToken.builder()
                .user(user)
                .tokenHash(hash(rawToken))
                .expiresAt(LocalDateTime.now().plusNanos(refreshTokenExpirationMs * 1_000_000))
                .revoked(false)
                .build();

        refreshTokenRepository.save(entity);
        return rawToken;
    }

    @Override
    @Transactional
    public User validateAndConsume(String rawToken) {
        RefreshToken entity = refreshTokenRepository.findByTokenHash(hash(rawToken))
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));

        if (!entity.isUsable()) {
            throw new InvalidRefreshTokenException("Refresh token is expired or has already been used");
        }

        // Single-use: this token is spent the moment it's redeemed, whether or not the
        // caller goes on to request a new one. A stolen-but-unused token that shows up
        // twice (attacker replaying it after the legitimate client already rotated) fails
        // here instead of silently succeeding.
        entity.setRevoked(true);
        refreshTokenRepository.save(entity);

        return entity.getUser();
    }

    @Override
    @Transactional
    public void revoke(String rawToken) {
        refreshTokenRepository.findByTokenHash(hash(rawToken))
                .ifPresent(entity -> {
                    entity.setRevoked(true);
                    refreshTokenRepository.save(entity);
                });
        // Deliberately a no-op (not an error) if the token doesn't exist - logging out
        // with an already-invalid token should still behave like a successful logout
        // from the client's point of view.
    }

    @Override
    @Transactional
    public void revokeAllForUser(Long userId) {
        refreshTokenRepository.deleteByUserId(userId);
    }

    private String generateRawToken() {
        byte[] bytes = new byte[64];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hash(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashed);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed available on every JVM - this branch is unreachable
            // in practice, but the checked exception has to go somewhere.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}

package com.labmentix.phishshield.service;

import com.labmentix.phishshield.entity.User;

public interface RefreshTokenService {

    /**
     * Issues a new refresh token for a user, persists its hash, and returns
     * the raw token - this is the only point the raw value ever exists
     * outside the client.
     */
    String issue(User user);

    /**
     * Validates a raw refresh token (exists, not expired, not revoked),
     * revokes it (single-use / rotation - see Day 18 doc), and returns the
     * owning user. Throws InvalidRefreshTokenException on any failure.
     */
    User validateAndConsume(String rawToken);

    /**
     * Revokes a single refresh token (logout on this device).
     */
    void revoke(String rawToken);

    /**
     * Revokes every refresh token belonging to a user (logout everywhere /
     * account disabled by an admin).
     */
    void revokeAllForUser(Long userId);
}

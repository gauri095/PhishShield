package com.labmentix.phishshield.dto;

import lombok.Builder;

@Builder
public record AuthResponse(
        String accessToken,
        String tokenType,
        String name,
        String email,
        String role
) {}

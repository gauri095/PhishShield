package com.labmentix.phishshield.dto;

import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record AdminUserResponse(
        Long id,
        String name,
        String email,
        String role,
        boolean enabled,
        LocalDateTime createdAt
) {}
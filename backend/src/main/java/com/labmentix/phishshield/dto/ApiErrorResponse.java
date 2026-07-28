package com.labmentix.phishshield.dto;

import lombok.Builder;

import java.time.LocalDateTime;
import java.util.List;

@Builder
public record ApiErrorResponse(
        LocalDateTime timestamp,
        int status,
        String error,
        String message,
        List<String> details
) {}

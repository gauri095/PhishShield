package com.labmentix.phishshield.dto;

import jakarta.validation.constraints.NotBlank;

public record EmailScanRequest(
        @NotBlank(message = "Email content is required")
        String emailContent
) {}

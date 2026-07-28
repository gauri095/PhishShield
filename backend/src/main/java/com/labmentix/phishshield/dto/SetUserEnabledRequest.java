package com.labmentix.phishshield.dto;

import jakarta.validation.constraints.NotNull;

public record SetUserEnabledRequest(
        @NotNull(message = "enabled is required")
        Boolean enabled
) {}
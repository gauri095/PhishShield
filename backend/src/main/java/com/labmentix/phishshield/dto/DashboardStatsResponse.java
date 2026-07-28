package com.labmentix.phishshield.dto;

import lombok.Builder;

@Builder
public record DashboardStatsResponse(
        long totalScans,
        long urlScans,
        long emailScans,
        long highRiskCount,
        long mediumRiskCount,
        long lowRiskCount
) {}

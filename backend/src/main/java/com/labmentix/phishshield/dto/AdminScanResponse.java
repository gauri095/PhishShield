package com.labmentix.phishshield.dto;

import com.labmentix.phishshield.enums.RiskLevel;
import com.labmentix.phishshield.enums.ScanType;
import com.labmentix.phishshield.enums.Verdict;
import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record AdminScanResponse(
        Long id,
        String userEmail,
        String userName,
        ScanType scanType,
        String content,
        int riskScore,
        RiskLevel riskLevel,
        Verdict verdict,
        LocalDateTime createdAt
) {}
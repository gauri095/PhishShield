package com.labmentix.phishshield.dto;   // <- adjust to your actual local package if it differs

import com.labmentix.phishshield.enums.RiskLevel;
import com.labmentix.phishshield.enums.ScanType;
import com.labmentix.phishshield.enums.Verdict;
import lombok.Builder;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Builder
public record ScanResultResponse(
        Long id,
        Long reportId,
        ScanType scanType,
        String content,
        int riskScore,
        RiskLevel riskLevel,
        Verdict verdict,
        List<String> reasons,
        Map<String, Object> details,
        LocalDateTime createdAt
) {}
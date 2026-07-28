package com.labmentix.phishshield.dto;

import com.labmentix.phishshield.enums.ReportType;
import com.labmentix.phishshield.enums.RiskLevel;
import com.labmentix.phishshield.enums.ScanType;
import com.labmentix.phishshield.enums.Verdict;
import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record ReportResponse(
        Long id,
        Long scanHistoryId,
        ReportType reportType,
        String reportDetails,
        ScanType scanType,
        String scannedContent,
        int riskScore,
        RiskLevel riskLevel,
        Verdict verdict,
        LocalDateTime createdAt
) {}
package com.labmentix.phishshield.service.impl;

import com.labmentix.phishshield.dto.DashboardStatsResponse;
import com.labmentix.phishshield.enums.RiskLevel;
import com.labmentix.phishshield.enums.ScanType;
import com.labmentix.phishshield.repository.ScanHistoryRepository;
import com.labmentix.phishshield.service.DashboardService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class DashboardServiceImpl implements DashboardService {

    private final ScanHistoryRepository scanHistoryRepository;

    @Override
    @Transactional(readOnly = true)
    public DashboardStatsResponse getGlobalStats() {
        long urlScans = scanHistoryRepository.countByScanType(ScanType.URL);
        long emailScans = scanHistoryRepository.countByScanType(ScanType.EMAIL);

        return DashboardStatsResponse.builder()
                .totalScans(urlScans + emailScans)
                .urlScans(urlScans)
                .emailScans(emailScans)
                .highRiskCount(scanHistoryRepository.countByRiskLevel(RiskLevel.HIGH))
                .mediumRiskCount(scanHistoryRepository.countByRiskLevel(RiskLevel.MEDIUM))
                .lowRiskCount(scanHistoryRepository.countByRiskLevel(RiskLevel.LOW))
                .build();
    }
}

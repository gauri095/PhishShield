package com.labmentix.phishshield.service.impl;

import com.labmentix.phishshield.dto.ReportResponse;
import com.labmentix.phishshield.entity.Report;
import com.labmentix.phishshield.entity.ScanHistory;
import com.labmentix.phishshield.enums.ReportType;
import com.labmentix.phishshield.enums.Role;
import com.labmentix.phishshield.enums.ScanType;
import com.labmentix.phishshield.exception.ResourceNotFoundException;
import com.labmentix.phishshield.repository.ReportRepository;
import com.labmentix.phishshield.security.AppUserPrincipal;
import com.labmentix.phishshield.service.ReportService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ReportServiceImpl implements ReportService {

    private final ReportRepository reportRepository;

    @Override
    @Transactional
    public Report generateReport(ScanHistory scan, List<String> reasons) {
        ReportType reportType = scan.getScanType() == ScanType.URL
                ? ReportType.URL_REPORT
                : ReportType.EMAIL_REPORT;

        String details = buildReportText(scan, reasons);

        Report report = Report.builder()
                .scanHistory(scan)
                .reportType(reportType)
                .reportDetails(details)
                .build();

        return reportRepository.save(report);
    }

    @Override
    @Transactional(readOnly = true)
    public ReportResponse getReport(Long reportId, AppUserPrincipal principal) {
        Report report = reportRepository.findById(reportId)
                .orElseThrow(() -> new ResourceNotFoundException("No report found with id " + reportId));

        return toResponseIfAuthorized(report, principal, "No report found with id " + reportId);
    }

    @Override
    @Transactional(readOnly = true)
    public ReportResponse getReportByScanId(Long scanHistoryId, AppUserPrincipal principal) {
        Report report = reportRepository.findByScanHistoryId(scanHistoryId).stream()
                .findFirst()
                .orElseThrow(() -> new ResourceNotFoundException(
                        "No report found for scan " + scanHistoryId));

        return toResponseIfAuthorized(report, principal,
                "No report found for scan " + scanHistoryId);
    }

    private ReportResponse toResponseIfAuthorized(Report report, AppUserPrincipal principal, String notFoundMessage) {
        boolean isOwner = report.getScanHistory().getUser().getId().equals(principal.getId());
        boolean isAdmin = principal.getUser().getRole() == Role.ADMIN;

        if (!isOwner && !isAdmin) {
            // Same message/status as "doesn't exist" - don't leak that a report
            // belongs to someone else.
            throw new ResourceNotFoundException(notFoundMessage);
        }

        ScanHistory scan = report.getScanHistory();

        return ReportResponse.builder()
                .id(report.getId())
                .scanHistoryId(scan.getId())
                .reportType(report.getReportType())
                .reportDetails(report.getReportDetails())
                .scanType(scan.getScanType())
                .scannedContent(scan.getContent())
                .riskScore(scan.getRiskScore())
                .riskLevel(scan.getRiskLevel())
                .verdict(scan.getVerdict())
                .createdAt(report.getCreatedAt())
                .build();
    }

    private String buildReportText(ScanHistory scan, List<String> reasons) {
        StringBuilder sb = new StringBuilder();
        sb.append("Scan Type: ").append(scan.getScanType()).append('\n');
        sb.append("Verdict: ").append(scan.getVerdict()).append('\n');
        sb.append("Risk Level: ").append(scan.getRiskLevel())
                .append(" (score ").append(scan.getRiskScore()).append("/100)").append('\n');
        sb.append('\n').append("Findings:").append('\n');

        if (reasons == null || reasons.isEmpty()) {
            sb.append("- No specific findings recorded.\n");
        } else {
            for (String reason : reasons) {
                sb.append("- ").append(reason).append('\n');
            }
        }

        return sb.toString();
    }
}
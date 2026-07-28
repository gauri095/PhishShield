package com.labmentix.phishshield.controller;

import com.labmentix.phishshield.dto.ReportResponse;
import com.labmentix.phishshield.security.AppUserPrincipal;
import com.labmentix.phishshield.service.ReportService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/reports")
@RequiredArgsConstructor
public class ReportController {

    private final ReportService reportService;

    @GetMapping("/{id}")
    public ResponseEntity<ReportResponse> getReport(
            @PathVariable Long id,
            @AuthenticationPrincipal AppUserPrincipal principal
    ) {
        return ResponseEntity.ok(reportService.getReport(id, principal));
    }

    @GetMapping("/scan/{scanHistoryId}")
    public ResponseEntity<ReportResponse> getReportByScanId(
            @PathVariable Long scanHistoryId,
            @AuthenticationPrincipal AppUserPrincipal principal
    ) {
        return ResponseEntity.ok(reportService.getReportByScanId(scanHistoryId, principal));
    }
}
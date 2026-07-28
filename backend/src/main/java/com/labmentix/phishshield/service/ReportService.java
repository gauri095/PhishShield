package com.labmentix.phishshield.service;

import com.labmentix.phishshield.dto.ReportResponse;
import com.labmentix.phishshield.entity.Report;
import com.labmentix.phishshield.entity.ScanHistory;
import com.labmentix.phishshield.security.AppUserPrincipal;

import java.util.List;

public interface ReportService {

    /**
     * Generates and persists a human-readable report for a just-completed scan.
     * Called internally by the scan services right after a ScanHistory is saved -
     * not exposed as its own "generate" endpoint since a report is 1:1 with a scan.
     */
    Report generateReport(ScanHistory scan, List<String> reasons);

    /**
     * Fetches a report by id. Only the scan's owner or an ADMIN may view it -
     * anyone else gets a 404 (not 403) so report IDs can't be used to probe
     * which ones exist.
     */
    ReportResponse getReport(Long reportId, AppUserPrincipal principal);

    /**
     * Convenience lookup for the frontend - History rows only know their
     * scanHistory id, not the report id generated alongside it, so this
     * saves the frontend from having to track a second id per scan.
     */
    ReportResponse getReportByScanId(Long scanHistoryId, AppUserPrincipal principal);
}
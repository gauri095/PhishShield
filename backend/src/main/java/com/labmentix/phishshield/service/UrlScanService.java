package com.labmentix.phishshield.service.impl;

import com.labmentix.phishshield.dto.ScanResultResponse;
import com.labmentix.phishshield.entity.Report;
import com.labmentix.phishshield.entity.ScanHistory;
import com.labmentix.phishshield.entity.User;
import com.labmentix.phishshield.enums.RiskLevel;
import com.labmentix.phishshield.enums.ScanType;
import com.labmentix.phishshield.enums.Verdict;
import com.labmentix.phishshield.exception.ExternalApiException;
import com.labmentix.phishshield.repository.ScanHistoryRepository;
import com.labmentix.phishshield.security.AppUserPrincipal;
import com.labmentix.phishshield.service.ReportService;
import com.labmentix.phishshield.service.UrlScanService;
import com.labmentix.phishshield.service.client.SafeBrowsingClient;
import com.labmentix.phishshield.service.client.VirusTotalClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class UrlScanServiceImpl implements UrlScanService {

    private static final Set<String> SUSPICIOUS_KEYWORDS = Set.of(
            "login", "verify", "update", "secure", "account", "confirm",
            "banking", "webscr", "signin", "password", "urgent", "suspend"
    );

    // A handful of well-known URL shorteners often abused to mask the real destination.
    private static final Set<String> SHORTENER_HOSTS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"
    );

    private final VirusTotalClient virusTotalClient;
    private final SafeBrowsingClient safeBrowsingClient;
    private final ScanHistoryRepository scanHistoryRepository;
    private final ReportService reportService;

    @Override
    @Transactional
    public ScanResultResponse scanUrl(String url, AppUserPrincipal principal) {
        List<String> reasons = new ArrayList<>();
        Map<String, Object> details = new HashMap<>();
        int score = 0;

        URI uri = safeParseUri(url);
        String host = uri != null && uri.getHost() != null ? uri.getHost().toLowerCase() : "";

        // --- Heuristic checks (always run, cheap, no external dependency) ---
        if (!url.toLowerCase().startsWith("https://")) {
            score += 15;
            reasons.add("URL does not use HTTPS");
        }

        long keywordHits = SUSPICIOUS_KEYWORDS.stream().filter(url.toLowerCase()::contains).count();
        if (keywordHits > 0) {
            score += (int) Math.min(30, keywordHits * 10);
            reasons.add("Contains " + keywordHits + " suspicious keyword(s) commonly used in phishing URLs");
        }

        if (SHORTENER_HOSTS.contains(host)) {
            score += 15;
            reasons.add("Uses a URL shortener, which can mask the real destination");
        }

        if (host.chars().filter(c -> c == '-').count() >= 3) {
            score += 10;
            reasons.add("Domain contains an unusually high number of hyphens");
        }

        details.put("heuristics", Map.of(
                "https", url.toLowerCase().startsWith("https://"),
                "suspiciousKeywordHits", keywordHits,
                "isShortener", SHORTENER_HOSTS.contains(host)
        ));

        // --- External API checks (best-effort; a failed provider degrades the
        // score confidence but never blocks the scan from completing) ---
        try {
            Map<String, Object> vtStats = virusTotalClient.analyzeUrl(url);
            if (!vtStats.isEmpty()) {
                details.put("virusTotal", vtStats);
                int malicious = asInt(vtStats.get("malicious"));
                int suspicious = asInt(vtStats.get("suspicious"));
                score += malicious * 12 + suspicious * 6;
                if (malicious > 0) {
                    reasons.add(malicious + " VirusTotal engine(s) flagged this URL as malicious");
                }
            }
        } catch (ExternalApiException ex) {
            details.put("virusTotalError", "unavailable");
        }

        try {
            boolean flagged = safeBrowsingClient.isFlagged(url);
            details.put("safeBrowsingFlagged", flagged);
            if (flagged) {
                score += 40;
                reasons.add("Flagged by Google Safe Browsing");
            }
        } catch (ExternalApiException ex) {
            details.put("safeBrowsingError", "unavailable");
        }

        score = Math.min(100, score);
        RiskLevel riskLevel = riskLevelFor(score);
        Verdict verdict = verdictFor(score);

        if (reasons.isEmpty()) {
            reasons.add("No suspicious indicators detected");
        }

        ScanHistory saved = scanHistoryRepository.save(ScanHistory.builder()
                .user(User.builder().id(principal.getId()).build())
                .content(url)
                .scanType(ScanType.URL)
                .riskScore(score)
                .riskLevel(riskLevel)
                .verdict(verdict)
                .details(details)
                .build());

        Report report = reportService.generateReport(saved, reasons);

        return ScanResultResponse.builder()
                .id(saved.getId())
                .reportId(report.getId())
                .scanType(ScanType.URL)
                .content(url)
                .riskScore(score)
                .riskLevel(riskLevel)
                .verdict(verdict)
                .reasons(reasons)
                .details(details)
                .createdAt(saved.getCreatedAt())
                .build();
    }

    private URI safeParseUri(String url) {
        try {
            return URI.create(url);
        } catch (Exception ex) {
            return null;
        }
    }

    private int asInt(Object value) {
        return value instanceof Number number ? number.intValue() : 0;
    }

    private RiskLevel riskLevelFor(int score) {
        if (score >= 70) return RiskLevel.HIGH;
        if (score >= 35) return RiskLevel.MEDIUM;
        return RiskLevel.LOW;
    }

    private Verdict verdictFor(int score) {
        if (score >= 70) return Verdict.MALICIOUS;
        if (score >= 35) return Verdict.SUSPICIOUS;
        return Verdict.SAFE;
    }
}

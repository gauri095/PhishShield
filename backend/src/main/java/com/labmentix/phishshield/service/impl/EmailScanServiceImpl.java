package com.labmentix.phishshield.service.impl;

import com.labmentix.phishshield.dto.ScanResultResponse;
import com.labmentix.phishshield.entity.Report;
import com.labmentix.phishshield.entity.ScanHistory;
import com.labmentix.phishshield.entity.User;
import com.labmentix.phishshield.enums.RiskLevel;
import com.labmentix.phishshield.enums.ScanType;
import com.labmentix.phishshield.enums.Verdict;
import com.labmentix.phishshield.repository.ScanHistoryRepository;
import com.labmentix.phishshield.security.AppUserPrincipal;
import com.labmentix.phishshield.service.EmailScanService;
import com.labmentix.phishshield.service.ReportService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class EmailScanServiceImpl implements EmailScanService {

    // Generic scam / social-engineering vocabulary.
    private static final Set<String> SCAM_KEYWORDS = Set.of(
            "congratulations", "you have won", "lottery", "claim your prize",
            "free gift", "act now", "limited time", "click here", "wire transfer",
            "inheritance", "beneficiary", "gift card"
    );

    // Language designed to pressure quick, unconsidered action.
    private static final Set<String> URGENCY_KEYWORDS = Set.of(
            "urgent", "immediately", "right away", "asap", "act now",
            "final notice", "account suspended", "within 24 hours", "expire"
    );

    // Attempts to harvest credentials or personal/financial info.
    private static final Set<String> CREDENTIAL_REQUEST_KEYWORDS = Set.of(
            "verify your account", "confirm your password", "enter your password",
            "update your billing", "social security number", "credit card number",
            "verify your identity", "login to your account", "reset your password"
    );

    private static final Pattern URL_PATTERN = Pattern.compile("https?://\\S+", Pattern.CASE_INSENSITIVE);

    private final ScanHistoryRepository scanHistoryRepository;
    private final ReportService reportService;

    @Override
    @Transactional
    public ScanResultResponse scanEmail(String emailContent, AppUserPrincipal principal) {
        String lower = emailContent.toLowerCase();
        List<String> reasons = new ArrayList<>();
        Map<String, Object> details = new HashMap<>();
        int score = 0;

        long scamHits = SCAM_KEYWORDS.stream().filter(lower::contains).count();
        long urgencyHits = URGENCY_KEYWORDS.stream().filter(lower::contains).count();
        long credentialHits = CREDENTIAL_REQUEST_KEYWORDS.stream().filter(lower::contains).count();

        List<String> links = extractLinks(emailContent);

        if (scamHits > 0) {
            score += (int) Math.min(30, scamHits * 10);
            reasons.add("Contains " + scamHits + " common scam phrase(s)");
        }
        if (urgencyHits > 0) {
            score += (int) Math.min(25, urgencyHits * 12);
            reasons.add("Uses urgent/pressuring language");
        }
        if (credentialHits > 0) {
            score += (int) Math.min(35, credentialHits * 15);
            reasons.add("Requests credentials or sensitive personal/financial information");
        }
        if (!links.isEmpty()) {
            score += Math.min(20, links.size() * 5);
            reasons.add("Contains " + links.size() + " embedded link(s)");
        }
        if (lower.contains("dear customer") || lower.contains("dear user") || lower.contains("dear account holder")) {
            score += 8;
            reasons.add("Uses a generic greeting instead of a personalized name");
        }

        score = Math.min(100, score);
        RiskLevel riskLevel = riskLevelFor(score);
        Verdict verdict = verdictFor(score);

        if (reasons.isEmpty()) {
            reasons.add("No suspicious indicators detected");
        }

        details.put("scamKeywordHits", scamHits);
        details.put("urgencyKeywordHits", urgencyHits);
        details.put("credentialRequestHits", credentialHits);
        details.put("linksFound", links);

        ScanHistory saved = scanHistoryRepository.save(ScanHistory.builder()
                .user(User.builder().id(principal.getId()).build())
                .content(emailContent)
                .scanType(ScanType.EMAIL)
                .riskScore(score)
                .riskLevel(riskLevel)
                .verdict(verdict)
                .details(details)
                .build());

        Report report = reportService.generateReport(saved, reasons);

        return ScanResultResponse.builder()
                .id(saved.getId())
                .reportId(report.getId())
                .scanType(ScanType.EMAIL)
                .content(emailContent)
                .riskScore(score)
                .riskLevel(riskLevel)
                .verdict(verdict)
                .reasons(reasons)
                .details(details)
                .createdAt(saved.getCreatedAt())
                .build();
    }

    private List<String> extractLinks(String content) {
        List<String> links = new ArrayList<>();
        Matcher matcher = URL_PATTERN.matcher(content);
        while (matcher.find()) {
            links.add(matcher.group());
        }
        return links;
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
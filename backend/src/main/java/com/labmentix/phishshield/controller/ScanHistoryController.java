package com.labmentix.phishshield.controller;

import com.labmentix.phishshield.entity.ScanHistory;
import com.labmentix.phishshield.repository.ScanHistoryRepository;
import com.labmentix.phishshield.security.AppUserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/scan-history")
@RequiredArgsConstructor
public class ScanHistoryController {

    private final ScanHistoryRepository scanHistoryRepository;

    @GetMapping("/me")
    public ResponseEntity<Page<ScanHistory>> myHistory(
            @AuthenticationPrincipal AppUserPrincipal principal,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        Pageable pageable = PageRequest.of(page, size);
        return ResponseEntity.ok(
                scanHistoryRepository.findByUserIdOrderByCreatedAtDesc(principal.getId(), pageable)
        );
    }
}

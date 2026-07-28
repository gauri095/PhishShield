package com.labmentix.phishshield.controller;

import com.labmentix.phishshield.dto.EmailScanRequest;
import com.labmentix.phishshield.dto.ScanResultResponse;
import com.labmentix.phishshield.dto.UrlScanRequest;
import com.labmentix.phishshield.security.AppUserPrincipal;
import com.labmentix.phishshield.service.EmailScanService;
import com.labmentix.phishshield.service.UrlScanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/scan")
@RequiredArgsConstructor
public class ScanController {

    private final UrlScanService urlScanService;
    private final EmailScanService emailScanService;

    @PostMapping("/url")
    public ResponseEntity<ScanResultResponse> scanUrl(
            @Valid @RequestBody UrlScanRequest request,
            @AuthenticationPrincipal AppUserPrincipal principal
    ) {
        return ResponseEntity.ok(urlScanService.scanUrl(request.url(), principal));
    }

    @PostMapping("/email")
    public ResponseEntity<ScanResultResponse> scanEmail(
            @Valid @RequestBody EmailScanRequest request,
            @AuthenticationPrincipal AppUserPrincipal principal
    ) {
        return ResponseEntity.ok(emailScanService.scanEmail(request.emailContent(), principal));
    }
}

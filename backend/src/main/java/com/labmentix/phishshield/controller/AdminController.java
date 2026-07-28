package com.labmentix.phishshield.controller;

import com.labmentix.phishshield.dto.AdminScanResponse;
import com.labmentix.phishshield.dto.AdminUserResponse;
import com.labmentix.phishshield.dto.SetUserEnabledRequest;
import com.labmentix.phishshield.security.AppUserPrincipal;
import com.labmentix.phishshield.service.AdminService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

/**
 * Every route here is already gated to ROLE_ADMIN by SecurityConfig
 * ("/api/admin/**" -> hasRole("ADMIN")) - no per-method @PreAuthorize needed.
 */
@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;

    @GetMapping("/users")
    public ResponseEntity<Page<AdminUserResponse>> listUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        Pageable pageable = PageRequest.of(page, size);
        return ResponseEntity.ok(adminService.listUsers(pageable));
    }

    @PatchMapping("/users/{id}/status")
    public ResponseEntity<AdminUserResponse> setUserEnabled(
            @PathVariable("id") Long userId,
            @Valid @RequestBody SetUserEnabledRequest request,
            @AuthenticationPrincipal AppUserPrincipal principal
    ) {
        return ResponseEntity.ok(
                adminService.setUserEnabled(userId, request.enabled(), principal.getId())
        );
    }

    @GetMapping("/scans")
    public ResponseEntity<Page<AdminScanResponse>> listAllScans(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        Pageable pageable = PageRequest.of(page, size);
        return ResponseEntity.ok(adminService.listAllScans(pageable));
    }
}
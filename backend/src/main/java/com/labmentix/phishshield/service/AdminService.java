package com.labmentix.phishshield.service;

import com.labmentix.phishshield.dto.AdminScanResponse;
import com.labmentix.phishshield.dto.AdminUserResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface AdminService {

    Page<AdminUserResponse> listUsers(Pageable pageable);

    AdminUserResponse setUserEnabled(Long userId, boolean enabled, Long actingAdminId);

    Page<AdminScanResponse> listAllScans(Pageable pageable);
}
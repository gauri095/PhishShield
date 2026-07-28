package com.labmentix.phishshield.service.impl;

import com.labmentix.phishshield.dto.AdminScanResponse;
import com.labmentix.phishshield.dto.AdminUserResponse;
import com.labmentix.phishshield.entity.ScanHistory;
import com.labmentix.phishshield.entity.User;
import com.labmentix.phishshield.exception.InvalidOperationException;
import com.labmentix.phishshield.exception.ResourceNotFoundException;
import com.labmentix.phishshield.repository.ScanHistoryRepository;
import com.labmentix.phishshield.repository.UserRepository;
import com.labmentix.phishshield.service.AdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AdminServiceImpl implements AdminService {

    private final UserRepository userRepository;
    private final ScanHistoryRepository scanHistoryRepository;

    @Override
    @Transactional(readOnly = true)
    public Page<AdminUserResponse> listUsers(Pageable pageable) {
        return userRepository.findAll(pageable).map(this::toUserResponse);
    }

    @Override
    @Transactional
    public AdminUserResponse setUserEnabled(Long userId, boolean enabled, Long actingAdminId) {
        if (userId.equals(actingAdminId) && !enabled) {
            throw new InvalidOperationException("You can't disable your own account");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("No user found with id " + userId));

        user.setEnabled(enabled);
        User saved = userRepository.save(user);
        return toUserResponse(saved);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<AdminScanResponse> listAllScans(Pageable pageable) {
        return scanHistoryRepository.findAllOrderByCreatedAtDesc(pageable).map(this::toScanResponse);
    }

    private AdminUserResponse toUserResponse(User user) {
        return AdminUserResponse.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .role(user.getRole().name())
                .enabled(user.isEnabled())
                .createdAt(user.getCreatedAt())
                .build();
    }

    private AdminScanResponse toScanResponse(ScanHistory scan) {
        return AdminScanResponse.builder()
                .id(scan.getId())
                .userEmail(scan.getUser().getEmail())
                .userName(scan.getUser().getName())
                .scanType(scan.getScanType())
                .content(scan.getContent())
                .riskScore(scan.getRiskScore())
                .riskLevel(scan.getRiskLevel())
                .verdict(scan.getVerdict())
                .createdAt(scan.getCreatedAt())
                .build();
    }
}
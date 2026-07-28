package com.labmentix.phishshield.service;

import com.labmentix.phishshield.dto.ScanResultResponse;
import com.labmentix.phishshield.security.AppUserPrincipal;

public interface EmailScanService {

    ScanResultResponse scanEmail(String emailContent, AppUserPrincipal principal);
}

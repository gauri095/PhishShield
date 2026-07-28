package com.labmentix.phishshield.service;

import com.labmentix.phishshield.dto.ScanResultResponse;
import com.labmentix.phishshield.security.AppUserPrincipal;

public interface UrlScanService {

    ScanResultResponse scanUrl(String url, AppUserPrincipal principal);
}

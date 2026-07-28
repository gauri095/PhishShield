package com.labmentix.phishshield.service;

import com.labmentix.phishshield.dto.AuthResponse;
import com.labmentix.phishshield.dto.LoginRequest;
import com.labmentix.phishshield.dto.RegisterRequest;

public interface AuthService {

    AuthResponse register(RegisterRequest request);

    AuthResponse login(LoginRequest request);
}

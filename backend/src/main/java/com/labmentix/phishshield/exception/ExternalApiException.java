package com.labmentix.phishshield.exception;

/**
 * Thrown when a call to an external security API (VirusTotal, Safe Browsing)
 * fails or times out. Callers should degrade gracefully rather than 500 the
 * whole scan - see UrlScanServiceImpl for how this is handled.
 */
public class ExternalApiException extends RuntimeException {
    public ExternalApiException(String message, Throwable cause) {
        super(message, cause);
    }
}

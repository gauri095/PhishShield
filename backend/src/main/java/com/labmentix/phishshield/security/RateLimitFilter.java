package com.labmentix.phishshield.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-user rate limit on POST /api/scan/** - protects the free-tier
 * VirusTotal/Safe Browsing quota from one user hammering the scan endpoints.
 *
 * In-memory rate limiting is enough because this app runs as a single instance.
 * If this ever runs as multiple instances behind a load balancer, each instance
 * would enforce its own separate limit.
 */
@Slf4j
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final String SCAN_PATH_PREFIX = "/api/scan/";

    private final ConcurrentHashMap<Long, RateLimitBucket> buckets = new ConcurrentHashMap<>();
    private final int requestsPerWindow;
    private final Duration window;

    public RateLimitFilter(
            @Value("${app.rate-limit.scan-requests-per-window}") int requestsPerWindow,
            @Value("${app.rate-limit.window-minutes}") long windowMinutes
    ) {
        this.requestsPerWindow = requestsPerWindow;
        this.window = Duration.ofMinutes(windowMinutes);
    }

    @Override
    protected void doFilterInternal(
             HttpServletRequest request,
             HttpServletResponse response,
             FilterChain filterChain
    ) throws ServletException, IOException {

        if (!isScanEndpoint(request) || !"POST".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        Long userId = extractUserId();
        if (userId == null) {
            filterChain.doFilter(request, response);
            return;
        }

        RateLimitBucket bucket = buckets.computeIfAbsent(userId, id -> new RateLimitBucket(requestsPerWindow, window));
        RateLimitResult result = bucket.tryConsume(1);

        response.setHeader("X-RateLimit-Limit", String.valueOf(requestsPerWindow));

        if (result.isConsumed()) {
            response.setHeader("X-RateLimit-Remaining", String.valueOf(result.getRemainingTokens()));
            filterChain.doFilter(request, response);
            return;
        }

        long retryAfterSeconds = result.getNanosToWaitForRefill() / 1_000_000_000L;
        response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
        response.setHeader("X-RateLimit-Remaining", "0");
        writeTooManyRequests(response, retryAfterSeconds);
    }

    private boolean isScanEndpoint(HttpServletRequest request) {
        return request.getRequestURI().startsWith(SCAN_PATH_PREFIX);
    }

    private Long extractUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getPrincipal() instanceof AppUserPrincipal principal)) {
            return null;
        }
        return principal.getId();
    }

    private void writeTooManyRequests(HttpServletResponse response, long retryAfterSeconds) throws IOException {
        response.setStatus(429);
        response.setContentType("application/json");

        String responseBody = String.format(
                "{\"timestamp\":\"%s\",\"status\":429,\"error\":\"Too Many Requests\",\"message\":\"Scan rate limit exceeded. Try again in %d seconds.\",\"details\":[\"Limit: %d scans per %d minutes\"]}",
                LocalDateTime.now(), retryAfterSeconds, requestsPerWindow, window.toMinutes()
        );

        response.getWriter().write(responseBody);
    }

    private static class RateLimitBucket {

        private final int capacity;
        private final long windowMillis;
        private long windowStart;
        private int remainingTokens;

        RateLimitBucket(int capacity, Duration window) {
            this.capacity = capacity;
            this.windowMillis = window.toMillis();
            this.windowStart = System.currentTimeMillis();
            this.remainingTokens = capacity;
        }

        synchronized RateLimitResult tryConsume(int tokens) {
            long now = System.currentTimeMillis();
            if (now - windowStart >= windowMillis) {
                windowStart = now;
                remainingTokens = capacity;
            }

            if (tokens <= remainingTokens) {
                remainingTokens -= tokens;
                return new RateLimitResult(true, remainingTokens, 0);
            }

            long waitMillis = windowMillis - (now - windowStart);
            if (waitMillis < 0) {
                waitMillis = 0;
            }

            return new RateLimitResult(false, 0, waitMillis * 1_000_000L);
        }
    }

    private static class RateLimitResult {

        private final boolean consumed;
        private final int remainingTokens;
        private final long nanosToWaitForRefill;

        RateLimitResult(boolean consumed, int remainingTokens, long nanosToWaitForRefill) {
            this.consumed = consumed;
            this.remainingTokens = remainingTokens;
            this.nanosToWaitForRefill = nanosToWaitForRefill;
        }

        boolean isConsumed() {
            return consumed;
        }

        int getRemainingTokens() {
            return remainingTokens;
        }

        long getNanosToWaitForRefill() {
            return nanosToWaitForRefill;
        }
    }
}

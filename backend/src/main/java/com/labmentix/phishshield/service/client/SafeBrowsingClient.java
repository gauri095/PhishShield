package com.labmentix.phishshield.service.client;

import com.labmentix.phishshield.exception.ExternalApiException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Thin wrapper around the Google Safe Browsing v4 "threatMatches:find" API.
 * https://developers.google.com/safe-browsing/v4/lookup-api
 */
@Slf4j
@Component
public class SafeBrowsingClient {

    private final WebClient webClient;
    private final String apiKey;

    public SafeBrowsingClient(
            WebClient safeBrowsingWebClient,
            @Value("${app.security-apis.safe-browsing.api-key}") String apiKey
    ) {
        this.webClient = safeBrowsingWebClient;
        this.apiKey = apiKey;
    }

    /**
     * Returns true if Safe Browsing flags the URL as malicious/unwanted.
     * Returns false (fail-open on the "is it flagged" question) if no API
     * key is configured or the request fails, and lets the caller fall back
     * on VirusTotal + keyword heuristics instead.
     */
    public boolean isFlagged(String url) {
        if (apiKey == null || apiKey.isBlank()) {
            log.warn("SAFE_BROWSING_API_KEY not configured - skipping Safe Browsing check");
            return false;
        }

        Map<String, Object> requestBody = Map.of(
                "client", Map.of("clientId", "phishing-detector", "clientVersion", "0.1.0"),
                "threatInfo", Map.of(
                        "threatTypes", List.of("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"),
                        "platformTypes", List.of("ANY_PLATFORM"),
                        "threatEntryTypes", List.of("URL"),
                        "threatEntries", List.of(Map.of("url", url))
                )
        );

        try {
            Map<?, ?> response = webClient.post()
                    .uri(uriBuilder -> uriBuilder
                            .path("/threatMatches:find")
                            .queryParam("key", apiKey)
                            .build())
                    .bodyValue(requestBody)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .timeout(Duration.ofSeconds(8))
                    .block();

            // An empty {} body means "no threats found"; a populated "matches" array means it's flagged.
            return response != null && response.containsKey("matches");

        } catch (Exception ex) {
            log.error("Safe Browsing lookup failed for url={}", url, ex);
            throw new ExternalApiException("Safe Browsing lookup failed", ex);
        }
    }
}

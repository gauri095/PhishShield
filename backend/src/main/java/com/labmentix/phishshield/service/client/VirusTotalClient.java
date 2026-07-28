package com.labmentix.phishshield.service.client;

import com.labmentix.phishshield.exception.ExternalApiException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.Base64;
import java.util.Map;

/**
 * Thin wrapper around the VirusTotal v3 URL analysis API.
 *
 * Flow: submit the URL for analysis, then fetch the report by its
 * URL-safe-base64-encoded id. See:
 * https://docs.virustotal.com/reference/url
 */
@Slf4j
@Component
public class VirusTotalClient {

    private final WebClient webClient;
    private final String apiKey;

    public VirusTotalClient(
            WebClient virusTotalWebClient,
            @Value("${app.security-apis.virustotal.api-key}") String apiKey
    ) {
        this.webClient = virusTotalWebClient;
        this.apiKey = apiKey;
    }

    /**
     * Returns the VirusTotal analysis stats map, e.g.
     * {"harmless": 70, "malicious": 3, "suspicious": 1, "undetected": 12, "timeout": 0}
     * Returns an empty map (rather than throwing) if no API key is configured,
     * so local dev / demo mode still works without a paid key.
     */
    public Map<String, Object> analyzeUrl(String url) {
        if (apiKey == null || apiKey.isBlank()) {
            log.warn("VIRUSTOTAL_API_KEY not configured - skipping VirusTotal check");
            return Map.of();
        }

        try {
            String urlId = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(url.getBytes());

            // Submit for (re)analysis is only needed for URLs VT hasn't seen; for a
            // portfolio-scale project, fetching the existing report is normally enough.
            Map<?, ?> response = webClient.get()
                    .uri("/urls/{id}", urlId)
                    .header("x-apikey", apiKey)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .timeout(Duration.ofSeconds(8))
                    .block();

            if (response == null) {
                return Map.of();
            }

            Map<?, ?> data = (Map<?, ?>) response.get("data");
            Map<?, ?> attributes = data != null ? (Map<?, ?>) data.get("attributes") : null;
            Object stats = attributes != null ? attributes.get("last_analysis_stats") : null;

            //noinspection unchecked
            return stats != null ? (Map<String, Object>) stats : Map.of();

        } catch (Exception ex) {
            log.error("VirusTotal lookup failed for url={}", url, ex);
            throw new ExternalApiException("VirusTotal lookup failed", ex);
        }
    }
}

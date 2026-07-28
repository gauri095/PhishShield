package com.labmentix.phishshield.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class WebClientConfig {

    @Bean
    public RestTemplate virusTotalRestTemplate() {
        return new RestTemplate();
    }

    @Bean
    public RestTemplate safeBrowsingRestTemplate() {
        return new RestTemplate();
    }
}

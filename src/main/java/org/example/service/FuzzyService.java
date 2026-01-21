package org.example.service;

import org.example.config.SecurityConfig;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

/**
 * Fuzzy matching service with secure URL handling.
 * Implements host allowlisting to prevent SSRF and open redirect attacks (CVE-2024-22243).
 */
@Service
public class FuzzyService {

    /**
     * Builds a validated URL for fuzzy search API calls.
     * Enforces host allowlisting to prevent SSRF attacks.
     * 
     * @param apiBaseUrl the base URL for the fuzzy search API
     * @param searchQuery the search query to append
     * @return the validated URI
     * @throws IllegalArgumentException if the host is not in the allowlist
     */
    public URI buildFuzzySearchUrl(String apiBaseUrl, String searchQuery) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(apiBaseUrl);
        
        // CVE-2024-22243 mitigation: Validate host against allowlist
        String host = builder.build().getHost();
        if (host == null || !SecurityConfig.ALLOWED_HOSTS.contains(host)) {
            throw new IllegalArgumentException("Untrusted host for fuzzy search API: " + host);
        }
        
        return builder.path("/api/fuzzy/search")
                     .queryParam("q", searchQuery)
                     .build()
                     .toUri();
    }

    /**
     * Validates a callback URL for fuzzy matching results.
     * Enforces host allowlisting to prevent open redirect and SSRF attacks.
     * 
     * @param callbackUrl the callback URL to validate
     * @return the validated URI
     * @throws IllegalArgumentException if the host is not in the allowlist
     */
    public URI validateCallbackUrl(String callbackUrl) {
        if (callbackUrl == null || callbackUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("Callback URL cannot be null or empty");
        }
        
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(callbackUrl);
        
        // CVE-2024-22243 mitigation: Validate host against allowlist
        String host = builder.build().getHost();
        if (host == null || !SecurityConfig.ALLOWED_HOSTS.contains(host)) {
            throw new IllegalArgumentException("Untrusted callback host: " + host);
        }
        
        return builder.build().toUri();
    }
}

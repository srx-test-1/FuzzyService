package org.example.service;

import org.example.config.SecurityConfig;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

/**
 * Service for managing inventory operations with secure URL handling.
 * Implements host allowlisting to prevent SSRF and open redirect attacks (CVE-2024-22243).
 */
@Service
public class InventoryManagementService {

    /**
     * Builds a validated external API URL for inventory lookups.
     * Enforces host allowlisting to prevent SSRF attacks.
     * 
     * @param baseUrl the base URL to validate
     * @param itemId the item ID to append to the URL
     * @return the validated URI
     * @throws IllegalArgumentException if the host is not in the allowlist
     */
    public URI buildInventoryApiUrl(String baseUrl, String itemId) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl);
        
        // CVE-2024-22243 mitigation: Validate host against allowlist
        String host = builder.build().getHost();
        if (host == null || !SecurityConfig.ALLOWED_HOSTS.contains(host)) {
            throw new IllegalArgumentException("Untrusted host for inventory API: " + host);
        }
        
        return builder.path("/api/inventory/").path(itemId).build().toUri();
    }

    /**
     * Validates and processes a redirect URL for inventory operations.
     * Enforces host allowlisting to prevent open redirect attacks.
     * 
     * @param redirectUrl the URL to validate for redirection
     * @return the validated URI
     * @throws IllegalArgumentException if the host is not in the allowlist
     */
    public URI validateRedirectUrl(String redirectUrl) {
        if (redirectUrl == null || redirectUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("Redirect URL cannot be null or empty");
        }
        
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectUrl);
        
        // CVE-2024-22243 mitigation: Validate host against allowlist
        String host = builder.build().getHost();
        if (host == null || !SecurityConfig.ALLOWED_HOSTS.contains(host)) {
            throw new IllegalArgumentException("Untrusted redirect host: " + host);
        }
        
        return builder.build().toUri();
    }
}

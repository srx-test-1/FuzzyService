package org.example;

import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Utility class for validating URIs to prevent SSRF and Open Redirect vulnerabilities.
 * This addresses CVE-2024-22259 by implementing strict host validation when using UriComponentsBuilder.
 */
public class UriValidator {
    
    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(Arrays.asList(
        "example.com",
        "www.example.com",
        "api.example.com",
        "localhost"
    ));
    
    /**
     * Validates a URL string and ensures the host is in the allowed list.
     * 
     * @param url The URL string to validate
     * @return true if the URL is valid and host is allowed, false otherwise
     */
    public static boolean isValidUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }
        
        try {
            UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(url);
            URI uri = builder.build().toUri();
            String host = uri.getHost();
            
            return isValidHost(host);
        } catch (Exception e) {
            // If parsing fails, the URL is invalid
            return false;
        }
    }
    
    /**
     * Checks if the provided host is in the allowed hosts list.
     * 
     * @param host The host to validate
     * @return true if host is allowed, false otherwise
     */
    public static boolean isValidHost(String host) {
        if (host == null || host.trim().isEmpty()) {
            return false;
        }
        
        // Normalize host to lowercase for comparison
        String normalizedHost = host.trim().toLowerCase();
        
        return ALLOWED_HOSTS.contains(normalizedHost);
    }
    
    /**
     * Validates a URL and throws an exception if it's invalid.
     * Use this method when you need to enforce validation.
     * 
     * @param url The URL string to validate
     * @throws IllegalArgumentException if the URL is invalid or host is not allowed
     */
    public static void validateUrlOrThrow(String url) {
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("URL cannot be null or empty");
        }
        
        try {
            UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(url);
            URI uri = builder.build().toUri();
            String host = uri.getHost();
            
            if (!isValidHost(host)) {
                throw new IllegalArgumentException("Invalid host: " + host + ". Host must be in the allowed list.");
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid URL format: " + url, e);
        }
    }
    
    /**
     * Gets an immutable copy of the allowed hosts set.
     * 
     * @return Set of allowed hosts
     */
    public static Set<String> getAllowedHosts() {
        return new HashSet<>(ALLOWED_HOSTS);
    }
}

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
    
    private static final Set<String> ALLOWED_SCHEMES = new HashSet<>(Arrays.asList(
        "http",
        "https"
    ));
    
    /**
     * Allowed hosts for URL validation.
     * 
     * WARNING: 'localhost' is included for demonstration/testing purposes only.
     * In production environments, carefully consider whether localhost access is necessary,
     * as it could potentially be exploited for SSRF attacks against local services.
     * Remove 'localhost' from this list if local access is not required.
     */
    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(Arrays.asList(
        "example.com",
        "www.example.com",
        "api.example.com",
        "localhost"  // WARNING: Consider removing in production if not needed
    ));
    
    /**
     * Validates a URL string and ensures the host is in the allowed list.
     * 
     * @param url The URL string to validate
     * @return true if the URL is valid and host is allowed, false otherwise
     */
    public static boolean isValidUrl(String url) {
        if (!isUrlNotEmpty(url)) {
            return false;
        }
        
        try {
            URI uri = extractAndValidateUri(url);
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
        if (!isUrlNotEmpty(url)) {
            throw new IllegalArgumentException("URL cannot be null or empty");
        }
        
        try {
            URI uri = extractAndValidateUri(url);
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
    
    /**
     * Private helper method to check if URL is not null or empty.
     * 
     * @param url The URL to check
     * @return true if URL is not null or empty, false otherwise
     */
    private static boolean isUrlNotEmpty(String url) {
        return url != null && !url.trim().isEmpty();
    }
    
    /**
     * Private helper method to extract and validate URI from URL using UriComponentsBuilder.
     * Only allows HTTP and HTTPS schemes to prevent SSRF attacks via file://, jar://, etc.
     * 
     * @param url The URL string to parse
     * @return The validated URI extracted from the URL
     * @throws IllegalArgumentException if the scheme is not allowed
     */
    private static URI extractAndValidateUri(String url) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(url);
        URI uri = builder.build().toUri();
        
        // Validate scheme - only allow HTTP/HTTPS to prevent file://, jar://, etc.
        String scheme = uri.getScheme();
        if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase())) {
            throw new IllegalArgumentException("Invalid or disallowed URL scheme: " + scheme + 
                ". Only HTTP and HTTPS are allowed.");
        }
        
        return uri;
    }
}


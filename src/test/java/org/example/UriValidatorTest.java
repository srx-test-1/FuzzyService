package org.example;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for UriValidator to ensure proper protection against
 * CVE-2024-22259 (SSRF/Open Redirect vulnerability).
 */
public class UriValidatorTest {
    
    @Test
    public void testValidUrlWithAllowedHost() {
        // Valid URLs with allowed hosts
        assertTrue(UriValidator.isValidUrl("https://example.com/path"));
        assertTrue(UriValidator.isValidUrl("http://www.example.com/path?param=value"));
        assertTrue(UriValidator.isValidUrl("https://api.example.com:8080/endpoint"));
        assertTrue(UriValidator.isValidUrl("http://localhost:3000/api"));
    }
    
    @Test
    public void testInvalidUrlWithDisallowedHost() {
        // Invalid URLs with disallowed hosts (potential SSRF targets)
        assertFalse(UriValidator.isValidUrl("https://evil.com/malicious"));
        assertFalse(UriValidator.isValidUrl("http://attacker.com/redirect"));
        assertFalse(UriValidator.isValidUrl("https://192.168.1.1/internal"));
        assertFalse(UriValidator.isValidUrl("http://10.0.0.1/private"));
    }
    
    @Test
    public void testNullAndEmptyUrls() {
        assertFalse(UriValidator.isValidUrl(null));
        assertFalse(UriValidator.isValidUrl(""));
        assertFalse(UriValidator.isValidUrl("   "));
    }
    
    @Test
    public void testMalformedUrls() {
        // Malformed URLs should return false
        assertFalse(UriValidator.isValidUrl("not-a-url"));
        assertFalse(UriValidator.isValidUrl("://missing-scheme"));
        assertFalse(UriValidator.isValidUrl("http://"));
    }
    
    @Test
    public void testHostValidation() {
        // Valid hosts
        assertTrue(UriValidator.isValidHost("example.com"));
        assertTrue(UriValidator.isValidHost("www.example.com"));
        assertTrue(UriValidator.isValidHost("api.example.com"));
        assertTrue(UriValidator.isValidHost("localhost"));
        
        // Case insensitive
        assertTrue(UriValidator.isValidHost("Example.Com"));
        assertTrue(UriValidator.isValidHost("LOCALHOST"));
        
        // Invalid hosts
        assertFalse(UriValidator.isValidHost("evil.com"));
        assertFalse(UriValidator.isValidHost("192.168.1.1"));
        assertFalse(UriValidator.isValidHost(null));
        assertFalse(UriValidator.isValidHost(""));
        assertFalse(UriValidator.isValidHost("   "));
    }
    
    @Test
    public void testValidateUrlOrThrowWithValidUrl() {
        // Should not throw exception for valid URLs
        assertDoesNotThrow(() -> UriValidator.validateUrlOrThrow("https://example.com/path"));
        assertDoesNotThrow(() -> UriValidator.validateUrlOrThrow("http://localhost/api"));
    }
    
    @Test
    public void testValidateUrlOrThrowWithInvalidHost() {
        // Should throw exception for disallowed hosts
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            UriValidator.validateUrlOrThrow("https://evil.com/malicious");
        });
        assertTrue(exception.getMessage().contains("Invalid host"));
    }
    
    @Test
    public void testValidateUrlOrThrowWithNullUrl() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            UriValidator.validateUrlOrThrow(null);
        });
        assertTrue(exception.getMessage().contains("URL cannot be null"));
    }
    
    @Test
    public void testValidateUrlOrThrowWithEmptyUrl() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            UriValidator.validateUrlOrThrow("");
        });
        assertTrue(exception.getMessage().contains("URL cannot be null or empty"));
    }
    
    @Test
    public void testValidateUrlOrThrowWithMalformedUrl() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            UriValidator.validateUrlOrThrow("not-a-valid-url");
        });
        assertTrue(exception.getMessage().contains("Invalid"));
    }
    
    @Test
    public void testOpenRedirectPrevention() {
        // Test URLs that could be used for open redirect attacks
        assertFalse(UriValidator.isValidUrl("https://example.com@evil.com"));
        assertFalse(UriValidator.isValidUrl("https://evil.com?redirect=example.com"));
    }
    
    @Test
    public void testSSRFPrevention() {
        // Test URLs targeting internal/private networks (SSRF attempts)
        assertFalse(UriValidator.isValidUrl("http://127.0.0.1/admin"));
        assertFalse(UriValidator.isValidUrl("http://[::1]/internal"));
        assertFalse(UriValidator.isValidUrl("http://169.254.169.254/metadata"));
    }
    
    @Test
    public void testGetAllowedHosts() {
        var allowedHosts = UriValidator.getAllowedHosts();
        assertNotNull(allowedHosts);
        assertTrue(allowedHosts.contains("example.com"));
        assertTrue(allowedHosts.contains("www.example.com"));
        assertTrue(allowedHosts.contains("api.example.com"));
        assertTrue(allowedHosts.contains("localhost"));
        assertEquals(4, allowedHosts.size());
    }
}

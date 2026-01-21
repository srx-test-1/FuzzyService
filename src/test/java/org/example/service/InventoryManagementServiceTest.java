package org.example.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for InventoryManagementService to verify CVE-2024-22243 mitigation.
 * Tests focus on host allowlisting and prevention of SSRF and open redirect attacks.
 */
class InventoryManagementServiceTest {

    private InventoryManagementService service;

    @BeforeEach
    void setUp() {
        service = new InventoryManagementService();
    }

    // Tests for buildInventoryApiUrl

    @Test
    void testBuildInventoryApiUrl_WithAllowedHost_Success() {
        // Test with allowed host
        URI result = service.buildInventoryApiUrl("http://example.com", "item123");
        assertNotNull(result);
        assertEquals("http://example.com/api/inventory/item123", result.toString());
    }

    @Test
    void testBuildInventoryApiUrl_WithLocalhost_Success() {
        // Test with localhost (allowed)
        URI result = service.buildInventoryApiUrl("http://localhost:8080", "item456");
        assertNotNull(result);
        assertTrue(result.toString().contains("localhost"));
        assertTrue(result.toString().contains("/api/inventory/item456"));
    }

    @Test
    void testBuildInventoryApiUrl_WithUntrustedHost_ThrowsException() {
        // Test SSRF prevention - untrusted host should be blocked
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildInventoryApiUrl("http://malicious.com", "item789")
        );
        assertTrue(exception.getMessage().contains("Untrusted host"));
        assertTrue(exception.getMessage().contains("malicious.com"));
    }

    @Test
    void testBuildInventoryApiUrl_WithExternalAttackerHost_ThrowsException() {
        // Test SSRF prevention - external attacker domain
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildInventoryApiUrl("http://attacker.evil.com", "item999")
        );
        assertTrue(exception.getMessage().contains("Untrusted host"));
    }

    @Test
    void testBuildInventoryApiUrl_WithInternalIP_ThrowsException() {
        // Test SSRF prevention - internal IP not in allowlist
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildInventoryApiUrl("http://192.168.1.1", "item000")
        );
        assertTrue(exception.getMessage().contains("Untrusted host"));
    }

    // Tests for validateRedirectUrl

    @Test
    void testValidateRedirectUrl_WithAllowedHost_Success() {
        // Test open redirect prevention - allowed host
        URI result = service.validateRedirectUrl("http://example.com/dashboard");
        assertNotNull(result);
        assertEquals("http://example.com/dashboard", result.toString());
    }

    @Test
    void testValidateRedirectUrl_WithTrustedPartner_Success() {
        // Test with trusted partner domain
        URI result = service.validateRedirectUrl("https://trusted-partner.com/callback");
        assertNotNull(result);
        assertEquals("https://trusted-partner.com/callback", result.toString());
    }

    @Test
    void testValidateRedirectUrl_WithUntrustedHost_ThrowsException() {
        // Test open redirect prevention - untrusted host should be blocked
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.validateRedirectUrl("http://phishing-site.com/steal-credentials")
        );
        assertTrue(exception.getMessage().contains("Untrusted redirect host"));
        assertTrue(exception.getMessage().contains("phishing-site.com"));
    }

    @Test
    void testValidateRedirectUrl_WithExternalMaliciousSite_ThrowsException() {
        // Test open redirect prevention - external malicious site
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.validateRedirectUrl("https://evil.com/redirect?target=victim")
        );
        assertTrue(exception.getMessage().contains("Untrusted redirect host"));
    }

    @Test
    void testValidateRedirectUrl_WithNullUrl_ThrowsException() {
        // Test input validation - null URL
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.validateRedirectUrl(null)
        );
        assertTrue(exception.getMessage().contains("cannot be null or empty"));
    }

    @Test
    void testValidateRedirectUrl_WithEmptyUrl_ThrowsException() {
        // Test input validation - empty URL
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.validateRedirectUrl("   ")
        );
        assertTrue(exception.getMessage().contains("cannot be null or empty"));
    }

    @Test
    void testValidateRedirectUrl_With127_0_0_1_Success() {
        // Test with 127.0.0.1 (allowed)
        URI result = service.validateRedirectUrl("http://127.0.0.1:8080/admin");
        assertNotNull(result);
        assertTrue(result.toString().contains("127.0.0.1"));
    }

    @Test
    void testValidateRedirectUrl_WithAPISubdomain_Success() {
        // Test with allowed API subdomain
        URI result = service.validateRedirectUrl("https://api.example.com/v1/users");
        assertNotNull(result);
        assertEquals("https://api.example.com/v1/users", result.toString());
    }
}

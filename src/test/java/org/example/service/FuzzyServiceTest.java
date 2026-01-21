package org.example.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for FuzzyService to verify CVE-2024-22243 mitigation.
 * Tests focus on host allowlisting and prevention of SSRF and open redirect attacks.
 */
class FuzzyServiceTest {

    private FuzzyService service;

    @BeforeEach
    void setUp() {
        service = new FuzzyService();
    }

    // Tests for buildFuzzySearchUrl

    @Test
    void testBuildFuzzySearchUrl_WithAllowedHost_Success() {
        // Test with allowed host
        URI result = service.buildFuzzySearchUrl("http://example.com", "test query");
        assertNotNull(result);
        assertTrue(result.toString().startsWith("http://example.com/api/fuzzy/search"));
        assertTrue(result.toString().contains("q="));
        assertTrue(result.toString().contains("test") && result.toString().contains("query"));
    }

    @Test
    void testBuildFuzzySearchUrl_WithLocalhost_Success() {
        // Test with localhost (allowed)
        URI result = service.buildFuzzySearchUrl("http://localhost:8080", "search term");
        assertNotNull(result);
        assertTrue(result.toString().contains("localhost"));
        assertTrue(result.toString().contains("/api/fuzzy/search"));
        assertTrue(result.toString().contains("q="));
        assertTrue(result.toString().contains("search") && result.toString().contains("term"));
    }

    @Test
    void testBuildFuzzySearchUrl_WithUntrustedHost_ThrowsException() {
        // Test SSRF prevention - untrusted host should be blocked
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildFuzzySearchUrl("http://malicious.com", "query")
        );
        assertTrue(exception.getMessage().contains("Untrusted host"));
        assertTrue(exception.getMessage().contains("malicious.com"));
    }

    @Test
    void testBuildFuzzySearchUrl_WithExternalAttackerHost_ThrowsException() {
        // Test SSRF prevention - external attacker domain
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildFuzzySearchUrl("http://attacker.evil.com", "malicious")
        );
        assertTrue(exception.getMessage().contains("Untrusted host"));
    }

    @Test
    void testBuildFuzzySearchUrl_WithInternalIP_ThrowsException() {
        // Test SSRF prevention - internal IP not in allowlist
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildFuzzySearchUrl("http://10.0.0.1", "internal")
        );
        assertTrue(exception.getMessage().contains("Untrusted host"));
    }

    @Test
    void testBuildFuzzySearchUrl_WithMetadataEndpoint_ThrowsException() {
        // Test SSRF prevention - cloud metadata endpoint
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildFuzzySearchUrl("http://169.254.169.254", "metadata")
        );
        assertTrue(exception.getMessage().contains("Untrusted host"));
    }

    // Tests for validateCallbackUrl

    @Test
    void testValidateCallbackUrl_WithAllowedHost_Success() {
        // Test callback validation with allowed host
        URI result = service.validateCallbackUrl("http://example.com/callback");
        assertNotNull(result);
        assertEquals("http://example.com/callback", result.toString());
    }

    @Test
    void testValidateCallbackUrl_WithTrustedPartner_Success() {
        // Test with trusted partner domain
        URI result = service.validateCallbackUrl("https://trusted-partner.com/webhook");
        assertNotNull(result);
        assertEquals("https://trusted-partner.com/webhook", result.toString());
    }

    @Test
    void testValidateCallbackUrl_WithUntrustedHost_ThrowsException() {
        // Test callback validation - untrusted host should be blocked
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.validateCallbackUrl("http://phishing-site.com/callback")
        );
        assertTrue(exception.getMessage().contains("Untrusted callback host"));
        assertTrue(exception.getMessage().contains("phishing-site.com"));
    }

    @Test
    void testValidateCallbackUrl_WithExternalMaliciousSite_ThrowsException() {
        // Test callback validation - external malicious site
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.validateCallbackUrl("https://evil.com/exfiltrate")
        );
        assertTrue(exception.getMessage().contains("Untrusted callback host"));
    }

    @Test
    void testValidateCallbackUrl_WithNullUrl_ThrowsException() {
        // Test input validation - null URL
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.validateCallbackUrl(null)
        );
        assertTrue(exception.getMessage().contains("cannot be null or empty"));
    }

    @Test
    void testValidateCallbackUrl_WithEmptyUrl_ThrowsException() {
        // Test input validation - empty URL
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.validateCallbackUrl("")
        );
        assertTrue(exception.getMessage().contains("cannot be null or empty"));
    }

    @Test
    void testValidateCallbackUrl_WithWhitespaceUrl_ThrowsException() {
        // Test input validation - whitespace URL
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.validateCallbackUrl("   ")
        );
        assertTrue(exception.getMessage().contains("cannot be null or empty"));
    }

    @Test
    void testValidateCallbackUrl_With127_0_0_1_Success() {
        // Test with 127.0.0.1 (allowed)
        URI result = service.validateCallbackUrl("http://127.0.0.1:9090/hook");
        assertNotNull(result);
        assertTrue(result.toString().contains("127.0.0.1"));
    }

    @Test
    void testValidateCallbackUrl_WithAPISubdomain_Success() {
        // Test with allowed API subdomain
        URI result = service.validateCallbackUrl("https://api.example.com/notifications");
        assertNotNull(result);
        assertEquals("https://api.example.com/notifications", result.toString());
    }
}

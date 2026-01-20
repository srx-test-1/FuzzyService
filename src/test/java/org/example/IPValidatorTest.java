package org.example;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test cases for IPValidator to ensure proper SSRF mitigation.
 * Tests cover CVE-2024-29415 equivalent edge cases.
 */
public class IPValidatorTest {
    
    // Test loopback addresses (should NOT be public)
    @Test
    public void testLoopbackIPv4Standard() {
        assertFalse(IPValidator.isPublic("127.0.0.1"), "Standard loopback should not be public");
        assertFalse(IPValidator.isPublic("127.0.0.2"), "Loopback range should not be public");
        assertFalse(IPValidator.isPublic("127.255.255.255"), "Loopback range should not be public");
    }
    
    @Test
    public void testLoopbackIPv4Abbreviated() {
        // CVE-2024-29415 edge case: abbreviated loopback
        assertFalse(IPValidator.isPublic("127.1"), "Abbreviated loopback (127.1) should not be public");
        assertFalse(IPValidator.isPublic("127.0.1"), "Abbreviated loopback (127.0.1) should not be public");
    }
    
    @Test
    public void testLoopbackIPv6() {
        assertFalse(IPValidator.isPublic("::1"), "IPv6 loopback should not be public");
        assertFalse(IPValidator.isPublic("0:0:0:0:0:0:0:1"), "IPv6 loopback (expanded) should not be public");
    }
    
    @Test
    public void testIPv6MappedLoopback() {
        // CVE-2024-29415 edge case: IPv4-mapped IPv6 loopback
        assertFalse(IPValidator.isPublic("::ffff:127.0.0.1"), "IPv4-mapped loopback should not be public");
        assertFalse(IPValidator.isPublic("::fFFf:127.0.0.1"), "IPv4-mapped loopback (mixed case) should not be public");
        assertFalse(IPValidator.isPublic("::FFFF:127.0.0.1"), "IPv4-mapped loopback (uppercase) should not be public");
    }
    
    @Test
    public void testOctalNotation() {
        // CVE-2024-29415 edge case: octal notation
        assertFalse(IPValidator.isPublic("0177.0.0.1"), "Octal loopback (0177.0.0.1) should not be public");
        assertFalse(IPValidator.isPublic("0177.1.2.3"), "Octal loopback should not be public");
    }
    
    @Test
    public void testPrivateIPv4Ranges() {
        // 10.0.0.0/8
        assertFalse(IPValidator.isPublic("10.0.0.1"), "10.x.x.x should not be public");
        assertFalse(IPValidator.isPublic("10.255.255.255"), "10.x.x.x should not be public");
        
        // 172.16.0.0/12
        assertFalse(IPValidator.isPublic("172.16.0.1"), "172.16-31.x.x should not be public");
        assertFalse(IPValidator.isPublic("172.31.255.255"), "172.16-31.x.x should not be public");
        
        // 192.168.0.0/16
        assertFalse(IPValidator.isPublic("192.168.0.1"), "192.168.x.x should not be public");
        assertFalse(IPValidator.isPublic("192.168.255.255"), "192.168.x.x should not be public");
    }
    
    @Test
    public void testPrivateIPv4Abbreviated() {
        assertFalse(IPValidator.isPublic("10.1"), "Abbreviated 10.x should not be public");
        assertFalse(IPValidator.isPublic("192.168"), "Abbreviated 192.168 should not be public");
    }
    
    @Test
    public void testLinkLocalAddresses() {
        // IPv4 link-local (169.254.0.0/16)
        assertFalse(IPValidator.isPublic("169.254.0.1"), "Link-local should not be public");
        assertFalse(IPValidator.isPublic("169.254.255.255"), "Link-local should not be public");
        
        // IPv6 link-local (fe80::/10)
        assertFalse(IPValidator.isPublic("fe80::1"), "IPv6 link-local should not be public");
    }
    
    @Test
    public void testMulticastAddresses() {
        // IPv4 multicast (224.0.0.0/4)
        assertFalse(IPValidator.isPublic("224.0.0.1"), "Multicast should not be public");
        assertFalse(IPValidator.isPublic("239.255.255.255"), "Multicast should not be public");
    }
    
    @Test
    public void testReservedAddresses() {
        // 0.0.0.0/8
        assertFalse(IPValidator.isPublic("0.0.0.0"), "0.0.0.0 should not be public");
        
        // 240.0.0.0/4 (reserved)
        assertFalse(IPValidator.isPublic("240.0.0.1"), "Reserved range should not be public");
        assertFalse(IPValidator.isPublic("255.255.255.255"), "Broadcast should not be public");
    }
    
    @Test
    public void testPublicIPv4Addresses() {
        // These should be considered public
        assertTrue(IPValidator.isPublic("8.8.8.8"), "Google DNS should be public");
        assertTrue(IPValidator.isPublic("1.1.1.1"), "Cloudflare DNS should be public");
        assertTrue(IPValidator.isPublic("208.67.222.222"), "OpenDNS should be public");
        assertTrue(IPValidator.isPublic("151.101.1.140"), "Public IP should be public");
    }
    
    @Test
    public void testPublicIPv6Addresses() {
        // These should be considered public
        assertTrue(IPValidator.isPublic("2001:4860:4860::8888"), "Google DNS IPv6 should be public");
        assertTrue(IPValidator.isPublic("2606:4700:4700::1111"), "Cloudflare DNS IPv6 should be public");
    }
    
    @Test
    public void testIPv6PrivateAddresses() {
        // Unique local addresses (fc00::/7)
        assertFalse(IPValidator.isPublic("fc00::1"), "Unique local address should not be public");
        assertFalse(IPValidator.isPublic("fd00::1"), "Unique local address should not be public");
    }
    
    @Test
    public void testIPv6MappedPrivate() {
        // IPv4-mapped IPv6 with private IPv4
        assertFalse(IPValidator.isPublic("::ffff:10.0.0.1"), "IPv4-mapped private should not be public");
        assertFalse(IPValidator.isPublic("::ffff:192.168.1.1"), "IPv4-mapped private should not be public");
    }
    
    @Test
    public void testEdgeCasesBoundary() {
        // Test boundaries of private ranges
        assertTrue(IPValidator.isPublic("11.0.0.1"), "11.x.x.x should be public (outside 10.0.0.0/8)");
        assertTrue(IPValidator.isPublic("172.15.255.255"), "172.15.x.x should be public (outside 172.16.0.0/12)");
        assertTrue(IPValidator.isPublic("172.32.0.1"), "172.32.x.x should be public (outside 172.16.0.0/12)");
        assertTrue(IPValidator.isPublic("192.167.1.1"), "192.167.x.x should be public (outside 192.168.0.0/16)");
        assertTrue(IPValidator.isPublic("192.169.1.1"), "192.169.x.x should be public (outside 192.168.0.0/16)");
    }
    
    @Test
    public void testInvalidInputs() {
        // Null and empty strings
        assertFalse(IPValidator.isPublic(null), "Null should not be public");
        assertFalse(IPValidator.isPublic(""), "Empty string should not be public");
        assertFalse(IPValidator.isPublic("   "), "Whitespace should not be public");
        
        // Invalid formats
        assertFalse(IPValidator.isPublic("not.an.ip.address"), "Invalid format should not be public");
        assertFalse(IPValidator.isPublic("999.999.999.999"), "Out of range octets should not be public");
    }
    
    @Test
    public void testWhitespaceHandling() {
        // Should handle whitespace
        assertFalse(IPValidator.isPublic(" 127.0.0.1 "), "Should trim whitespace from loopback");
        assertTrue(IPValidator.isPublic(" 8.8.8.8 "), "Should trim whitespace from public IP");
    }
    
    @Test
    public void testSpecificCVECases() {
        // Specific test cases from CVE-2024-29415
        assertFalse(IPValidator.isPublic("127.1"), "CVE case: 127.1 should not be public");
        assertFalse(IPValidator.isPublic("012.1.2.3"), "CVE case: octal 012.1.2.3 should not be public");
        assertFalse(IPValidator.isPublic("::fFFf:127.0.0.1"), "CVE case: ::fFFf:127.0.0.1 should not be public");
    }
}

package org.example;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/**
 * Utility class for validating IP addresses to prevent SSRF attacks.
 * Addresses CVE-2024-29415 equivalent vulnerability by properly identifying
 * private/loopback IP addresses including edge cases.
 */
public class IPValidator {
    
    // Pattern for detecting octal notation (leading zeros)
    private static final Pattern OCTAL_PATTERN = Pattern.compile("^0[0-7]+$");
    
    /**
     * Determines if an IP address is public (safe to use for external connections).
     * 
     * Edge cases handled:
     * - Abbreviated IPs like 127.1 (should be treated as loopback)
     * - Octal notation like 012.1.2.3 (should be normalized)
     * - IPv6 addresses like ::fFFf:127.0.0.1 (IPv4-mapped loopback)
     * 
     * @param ipAddress The IP address to validate (can be IPv4 or IPv6)
     * @return true if the IP is public (safe for external use), false otherwise
     */
    public static boolean isPublic(String ipAddress) {
        if (ipAddress == null || ipAddress.trim().isEmpty()) {
            return false;
        }
        
        try {
            // Normalize the IP address first to handle edge cases
            String normalizedIP = normalizeIPAddress(ipAddress.trim());
            
            // Check if normalization detected a private/loopback IP
            if (normalizedIP == null) {
                return false;
            }
            
            // Use InetAddress for standard validation
            InetAddress address = InetAddress.getByName(normalizedIP);
            
            // Check if it's loopback (127.0.0.0/8 for IPv4, ::1 for IPv6)
            if (address.isLoopbackAddress()) {
                return false;
            }
            
            // Check if it's a site-local address (private networks)
            if (address.isSiteLocalAddress()) {
                return false;
            }
            
            // Check if it's a link-local address (169.254.0.0/16 for IPv4, fe80::/10 for IPv6)
            if (address.isLinkLocalAddress()) {
                return false;
            }
            
            // Additional checks for private IP ranges not caught by Java's built-in methods
            byte[] bytes = address.getAddress();
            
            // IPv4 checks
            if (bytes.length == 4) {
                return isPublicIPv4(bytes);
            }
            
            // IPv6 checks
            if (bytes.length == 16) {
                return isPublicIPv6(bytes);
            }
            
            return true;
            
        } catch (UnknownHostException e) {
            // If we can't parse the IP, treat it as non-public for safety
            return false;
        }
    }
    
    /**
     * Normalizes IP addresses to handle edge cases like abbreviated IPs and octal notation.
     * Returns null if the IP is detected as private/loopback during normalization.
     */
    private static String normalizeIPAddress(String ipAddress) {
        // Handle IPv6 addresses with embedded IPv4 (like ::fFFf:127.0.0.1)
        if (ipAddress.toLowerCase().contains("::ffff:") || 
            ipAddress.toLowerCase().contains("::0ffff:")) {
            // Extract the IPv4 part
            String[] parts = ipAddress.split(":");
            String lastPart = parts[parts.length - 1];
            
            // Check if the embedded IPv4 is loopback or private
            if (lastPart.contains(".")) {
                String normalizedIPv4 = normalizeIPv4(lastPart);
                if (normalizedIPv4 == null) {
                    return null; // It's a private/loopback IP
                }
                // Return the full IPv6 address but we know it needs further checking
                return ipAddress;
            }
        }
        
        // Handle IPv4 addresses (including abbreviated and octal)
        if (ipAddress.contains(".") && !ipAddress.contains(":")) {
            return normalizeIPv4(ipAddress);
        }
        
        return ipAddress;
    }
    
    /**
     * Normalizes IPv4 addresses, handling abbreviated notation and octal.
     * Returns null if the IP is detected as loopback or private during normalization.
     */
    private static String normalizeIPv4(String ipv4) {
        String[] octets = ipv4.split("\\.");
        
        // Handle abbreviated IPs (e.g., 127.1 means 127.0.0.1)
        if (octets.length < 4) {
            // First octet determines if it's loopback
            int firstOctet = parseOctet(octets[0]);
            if (firstOctet == 127) {
                // This is a loopback address
                return null;
            }
            // Check for other private ranges
            if (firstOctet == 10) {
                return null; // 10.0.0.0/8
            }
            if (firstOctet == 172 && octets.length >= 2) {
                int secondOctet = parseOctet(octets[1]);
                if (secondOctet >= 16 && secondOctet <= 31) {
                    return null; // 172.16.0.0/12
                }
            }
            if (firstOctet == 192 && octets.length >= 2) {
                int secondOctet = parseOctet(octets[1]);
                if (secondOctet == 168) {
                    return null; // 192.168.0.0/16
                }
            }
        }
        
        // Parse and normalize all octets (handles octal notation)
        StringBuilder normalized = new StringBuilder();
        for (int i = 0; i < octets.length; i++) {
            int octetValue = parseOctet(octets[i]);
            if (octetValue < 0 || octetValue > 255) {
                return ipv4; // Invalid, let InetAddress handle it
            }
            
            if (i > 0) {
                normalized.append(".");
            }
            normalized.append(octetValue);
        }
        
        // Pad with zeros if abbreviated
        while (octets.length < 4) {
            normalized.append(".0");
            octets = new String[octets.length + 1]; // Just for loop control
        }
        
        String result = normalized.toString();
        
        // Check if first octet is 127 (loopback)
        if (result.startsWith("127.")) {
            return null;
        }
        
        return result;
    }
    
    /**
     * Parses an octet, handling decimal and octal notation.
     * Returns -1 if the octet cannot be parsed.
     */
    private static int parseOctet(String octet) {
        try {
            if (octet.startsWith("0") && octet.length() > 1) {
                // Could be octal
                if (OCTAL_PATTERN.matcher(octet).matches()) {
                    return Integer.parseInt(octet, 8); // Parse as octal
                }
            }
            return Integer.parseInt(octet);
        } catch (NumberFormatException e) {
            return -1; // Invalid octet
        }
    }
    
    /**
     * Additional checks for IPv4 addresses to ensure they're public.
     */
    private static boolean isPublicIPv4(byte[] bytes) {
        int first = bytes[0] & 0xFF;
        int second = bytes[1] & 0xFF;
        
        // 0.0.0.0/8 - Current network
        if (first == 0) {
            return false;
        }
        
        // 10.0.0.0/8 - Private network
        if (first == 10) {
            return false;
        }
        
        // 127.0.0.0/8 - Loopback (already checked but double-check)
        if (first == 127) {
            return false;
        }
        
        // 169.254.0.0/16 - Link-local (already checked but double-check)
        if (first == 169 && second == 254) {
            return false;
        }
        
        // 172.16.0.0/12 - Private network
        if (first == 172 && second >= 16 && second <= 31) {
            return false;
        }
        
        // 192.168.0.0/16 - Private network
        if (first == 192 && second == 168) {
            return false;
        }
        
        // 224.0.0.0/4 - Multicast
        if (first >= 224 && first <= 239) {
            return false;
        }
        
        // 240.0.0.0/4 - Reserved
        if (first >= 240) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Additional checks for IPv6 addresses to ensure they're public.
     */
    private static boolean isPublicIPv6(byte[] bytes) {
        // Check for IPv4-mapped IPv6 addresses (::ffff:0:0/96)
        boolean isIPv4Mapped = true;
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) {
                isIPv4Mapped = false;
                break;
            }
        }
        if (isIPv4Mapped && bytes[10] == (byte) 0xff && bytes[11] == (byte) 0xff) {
            // Extract the IPv4 part and check it
            byte[] ipv4Bytes = new byte[4];
            System.arraycopy(bytes, 12, ipv4Bytes, 0, 4);
            return isPublicIPv4(ipv4Bytes);
        }
        
        // Check for unique local addresses (fc00::/7)
        if ((bytes[0] & 0xfe) == 0xfc) {
            return false;
        }
        
        // All other checks are handled by Java's built-in methods
        return true;
    }
}

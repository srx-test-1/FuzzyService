package org.example.config;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.springframework.context.annotation.Configuration;

/**
 * Security configuration for allowed hosts to prevent SSRF and open redirect attacks.
 */
@Configuration
public class SecurityConfig {
    
    /**
     * Allowlist of trusted hosts for URL redirects and external requests.
     * Only URLs with these hosts will be allowed.
     */
    public static final Set<String> ALLOWED_HOSTS = new HashSet<>(Arrays.asList(
        "localhost",
        "127.0.0.1",
        "example.com",
        "api.example.com",
        "trusted-partner.com"
    ));
}

# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Security

#### CVE-2024-22243: Open Redirect/SSRF Vulnerability Fixed
- **Fixed**: Upgraded Spring Boot from 2.5.10 to 2.7.18 to address CVE-2024-22243
  - This update includes Spring Framework 5.3.32 which patches the UriComponentsBuilder vulnerability
- **Added**: Host allowlisting mechanism to prevent SSRF and open redirect attacks
  - Created `SecurityConfig` class with `ALLOWED_HOSTS` configuration
  - Implemented host validation in all UriComponentsBuilder usages
- **Added**: Input validation for all redirect URLs and external API calls
  - Validates against null, empty, and untrusted hosts
  - Throws `IllegalArgumentException` for invalid or untrusted URLs

### Added
- **New Service**: `InventoryManagementService`
  - `buildInventoryApiUrl()`: Builds validated URLs for inventory API calls with host allowlisting
  - `validateRedirectUrl()`: Validates redirect URLs against the allowlist
- **New Service**: `FuzzyService`
  - `buildFuzzySearchUrl()`: Builds validated URLs for fuzzy search API calls with host allowlisting
  - `validateCallbackUrl()`: Validates callback URLs against the allowlist
- **New Controllers**: REST endpoints for inventory and fuzzy search operations
  - `InventoryController`: Endpoints for inventory URL validation
  - `FuzzyController`: Endpoints for fuzzy search URL validation
- **New Tests**: Comprehensive unit tests for CVE-2024-22243 mitigation
  - `InventoryManagementServiceTest`: 14 tests covering SSRF and open redirect scenarios
  - `FuzzyServiceTest`: 14 tests covering SSRF and open redirect scenarios
  - Tests validate both allowed and blocked hosts
  - Tests cover edge cases (null, empty, internal IPs, cloud metadata endpoints)

### Changed
- **Dependencies**:
  - Spring Boot: 2.5.10 → 2.7.18 (includes Spring Framework 5.3.32)
  - Added spring-boot-starter-test 2.7.18 for testing support
- **Application Structure**:
  - Added Spring Boot application entry point (`Application.java`)
  - Organized code into packages: config, service, controller

### Technical Details

#### Host Allowlist
The following hosts are currently allowed:
- localhost
- 127.0.0.1
- example.com
- api.example.com
- trusted-partner.com

To add more trusted hosts, update `SecurityConfig.ALLOWED_HOSTS`.

#### Validation Logic
All UriComponentsBuilder usages now follow this pattern:
```java
UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(url);
String host = builder.build().getHost();
if (host == null || !SecurityConfig.ALLOWED_HOSTS.contains(host)) {
    throw new IllegalArgumentException("Untrusted host: " + host);
}
```

This prevents:
1. **SSRF (Server-Side Request Forgery)**: Attackers cannot make the server send requests to internal resources or cloud metadata endpoints
2. **Open Redirect**: Attackers cannot redirect users to phishing or malicious sites

### Testing
All tests pass successfully:
- 28 unit tests total
- 14 tests for InventoryManagementService
- 14 tests for FuzzyService
- Tests cover both positive (allowed hosts) and negative (blocked hosts) scenarios

## References
- [CVE-2024-22243 Official Advisory](https://spring.io/security/cve-2024-22243)
- [Spring Framework Security Documentation](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-uri-building.html)

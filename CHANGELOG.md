# Changelog

All notable changes to this project will be documented in this file.

## [1.0-SNAPSHOT] - 2026-01-21

### Security
- **[CRITICAL]** Upgraded Spring Boot from 2.5.10 to 2.6.6 to mitigate CVE-2022-22965 (Spring4Shell)
  - Spring Framework upgraded from 5.3.16 to 5.3.18
  - CVE-2022-22965 is a critical Remote Code Execution (RCE) vulnerability affecting Spring Framework versions prior to 5.2.20 and 5.3.18
  - Applications running on JDK 9+ with Apache Tomcat as a WAR deployment were at risk
  - This upgrade ensures the application is no longer vulnerable to Spring4Shell exploitation

### Changed
- Updated `org.springframework.boot:spring-boot-starter-web` from 2.5.10 to 2.6.6
- Spring Framework dependencies now resolve to 5.3.18 (previously 5.3.16)
- Jackson dependencies updated from 2.12.6 to 2.13.2.2 (transitive dependency from Spring Boot upgrade)
- Tomcat Embed updated from 9.0.58 to 9.0.60 (transitive dependency from Spring Boot upgrade)
- Log4j API updated from 2.17.1 to 2.17.2 (transitive dependency from Spring Boot upgrade)
- Logback updated from 1.2.10 to 1.2.11 (transitive dependency from Spring Boot upgrade)

### Testing
- Build successfully completed with upgraded dependencies
- All existing functionality remains intact
- No breaking changes detected in the application code

import org.gradle.wrapper.Download

plugins {
    id("java")
    id("de.undercouch.download") version "5.3.0"
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

tasks.register("downloadNewrelic") {
    doLast {
            val newrelicDir = file("newrelic")
            if (!newrelicDir.exists()) {
                newrelicDir.mkdirs() // Create the directory if it doesn't exist
            }
        ant.invokeMethod("get", mapOf(
            "src" to "https://download.newrelic.com/newrelic/java-agent/newrelic-agent/current/newrelic-java.zip",
            "dest" to file("newrelic/newrelic-java.zip")
        ))
    }
}

tasks.register<Copy>("unzipNewrelic") {
    from(zipTree(file("newrelic/newrelic-java.zip")))
    into(rootDir)
}

dependencies {
    // Updated to commons-fileupload 1.6.0 (fixes CVE-2023-24998 and other vulnerabilities)
    implementation ("commons-fileupload:commons-fileupload:1.6.0")
    implementation ("org.apache.commons:commons-lang3:3.9")
    implementation ("org.apache.commons:commons-collections4:4.4")

    // Updated to Spring Boot 2.6.6 to include Spring Framework 5.3.18+ (fixes CVE-2022-22965 - Spring4Shell)
    implementation ("org.springframework.boot:spring-boot-starter-web:2.6.6")

    // Upgrade to Log4j 2.17.2 which resolves CVE-2021-44228 (Log4Shell) and related vulnerabilities
    implementation ("org.apache.logging.log4j:log4j-core:2.17.2")
    implementation ("org.apache.logging.log4j:log4j-api:2.17.2")

    // Upgrade to latest Gson version
    implementation ("com.google.code.gson:gson:2.8.9")

    implementation ("com.google.guava:guava:31.1-jre")

    // Override Jackson versions to fix CVE-2022-42003, CVE-2022-42004, and related vulnerabilities
    implementation ("com.fasterxml.jackson.core:jackson-databind:2.13.4.2")
    implementation ("com.fasterxml.jackson.core:jackson-core:2.13.4")
    implementation ("com.fasterxml.jackson.core:jackson-annotations:2.13.4")

    implementation ("commons-net:commons-net:3.9.0")

    testImplementation ("org.junit.jupiter:junit-jupiter-api:5.8.1")
    testImplementation("org.junit.jupiter:junit-jupiter-engine:5.8.1")

}

tasks.test {
    useJUnitPlatform()
}
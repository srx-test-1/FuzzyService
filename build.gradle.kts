import org.gradle.wrapper.Download

plugins {
    id("java")
    id("de.undercouch.download") version "5.3.0"
    id("io.spring.dependency-management") version "1.1.0"
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

// Configure dependency management to override Spring Framework version to patch CVE-2024-22259
// Using 5.3.39 (latest available in 5.3.x line) which includes CVE-2024-22259 fix
// Note: Some vulnerabilities in 5.3.x line have no patches available and require migration to Spring 6.x
dependencyManagement {
    imports {
        mavenBom("org.springframework.boot:spring-boot-dependencies:2.7.18")
    }
    dependencies {
        dependency("org.springframework:spring-core:5.3.39")
        dependency("org.springframework:spring-context:5.3.39")
        dependency("org.springframework:spring-web:5.3.39")
        dependency("org.springframework:spring-webmvc:5.3.39")
        dependency("org.springframework:spring-beans:5.3.39")
        dependency("org.springframework:spring-aop:5.3.39")
        dependency("org.springframework:spring-expression:5.3.39")
        dependency("org.springframework:spring-jcl:5.3.39")
    }
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
    implementation ("commons-fileupload:commons-fileupload:1.3.3")
    implementation ("org.apache.commons:commons-lang3:3.9")
    implementation ("org.apache.commons:commons-collections4:4.4")

    implementation ("org.springframework.boot:spring-boot-starter-web:2.7.18") // Updated to patch CVE-2024-22259

    // Upgrade to Log4j2 which resolves vulnerabilities found in Log4j 1.x
    implementation ("org.apache.logging.log4j:log4j-core:2.14.1")
    implementation ("org.apache.logging.log4j:log4j-api:2.14.1")

    // Upgrade to latest Gson version
    implementation ("com.google.code.gson:gson:2.8.9")


    implementation ("com.google.guava:guava:18.0")

    implementation ("com.fasterxml.jackson.core:jackson-databind:2.8.11")

    implementation ("com.fasterxml.jackson.core:jackson-core:2.8.11")

    implementation ("com.fasterxml.jackson.core:jackson-annotations:2.8.11")

    implementation ("commons-net:commons-net:3.6")


    testImplementation ("org.junit.jupiter:junit-jupiter-api:5.8.1")
    testImplementation("org.junit.jupiter:junit-jupiter-engine:5.8.1")

}

tasks.test {
    useJUnitPlatform()
}
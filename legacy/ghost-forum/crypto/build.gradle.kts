plugins {
    kotlin("jvm")
    `maven-publish`
}

repositories {
    mavenCentral()
    mavenLocal()
}

dependencies {
    implementation(project(':crypto'))
    implementation(kotlin("stdlib"))
    
    // Cryptography libraries
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
    
    // Signal Protocol for Double Ratchet
    implementation("org.whispersystems:signal-protocol-java:2.8.1")
    
    // Testing libraries
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5:2.0.0")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.0")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.0")
}

tasks.test {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = "com.ghost.forum"
            artifactId = "crypto"
            version = "1.0.0"
            
            from(components["java"])
        }
    }
}
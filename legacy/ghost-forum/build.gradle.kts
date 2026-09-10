plugins {
    kotlin("jvm") version "2.0.0"
    `maven-publish`
    alias(libs.plugins.kotlin.jvm)
}

group = "com.ghost.forum"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib"))
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}
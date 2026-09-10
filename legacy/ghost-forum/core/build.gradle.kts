plugins {
    kotlin("jvm")
}

dependencies {
    implementation(project(":crypto"))
    implementation(kotlin("stdlib"))
    testImplementation(kotlin("test"))
}
plugins {
    kotlin("jvm")
}

dependencies {
    implementation(project(":core"))
    implementation(project(":crypto"))
    implementation(project(":relay"))
    implementation(project(":storage"))
    implementation(project(":api"))
    implementation(kotlin("stdlib"))
    testImplementation(kotlin("test"))
}
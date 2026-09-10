plugins {
    kotlin("jvm")
}

dependencies {
    implementation(project(":core"))
    implementation(kotlin("stdlib"))
    // SQLCipher for encrypted storage
    implementation("net.zetetic:android-database-sqlcipher:4.5.0")
    testImplementation(kotlin("test"))
}
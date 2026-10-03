// V-M15 (partial, manifest level only): can memtagMode be declared for the isolated `:mdec`
// process alone (a <processes>/<process> entry) and does the package manager accept it? The
// emulator is x86_64 without MTE, so nothing about the runtime effect can be seen here.
plugins { id("com.android.application") }
android {
    namespace = "org.ghost.spike.mte"
    compileSdk = 37
    defaultConfig { applicationId = "org.ghost.spike.mte"; minSdk = 29; targetSdk = 37 }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}

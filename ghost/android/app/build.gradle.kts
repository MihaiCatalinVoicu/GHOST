plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "org.ghost.app"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "org.ghost.app"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        versionCode = 1
        versionName = "0.1.0-devpreview"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Signing is done offline (FR-8.2, ADR-07); CI produces the unsigned, reproducible artifact.
        }
        debug {
            applicationIdSuffix = ".debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = false
    }

    packaging {
        // Reproducibility: drop build-host metadata that varies between machines.
        resources.excludes += setOf("META-INF/*.version", "META-INF/DEPENDENCIES", "kotlin/**")
    }

    dependenciesInfo {
        // Do not embed the Play Store dependency block: it is encrypted with a Google key and
        // breaks independent reproducibility verification (ADR-07).
        includeInApk = false
        includeInBundle = false
    }
}

dependencies {
    implementation(project(":identity"))
    implementation(project(":crypto-bridge"))
    implementation(project(":messaging"))
    implementation(project(":storage"))
    implementation(project(":sync"))
    implementation(project(":network"))
    implementation(project(":entitlement"))
    implementation(project(":media"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)

    testImplementation(libs.junit)
}

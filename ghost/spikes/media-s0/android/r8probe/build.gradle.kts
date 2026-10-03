// V-M7 / V-M14: a minimal app in two flavours, built as R8-shrunk releases like ghost/android's
// :app (isMinifyEnabled, isShrinkResources, proguard-android-optimize). `base` holds no Media3;
// `media` uses Media3 exactly the way design §8.3 and §10.2 do (player through a GHOST DataSource
// and a FragmentedMp4Extractor-only factory, Transformer with a custom muxer and ContentDataSource).
// The release dex of `media` is listed for the classes G-M1 bans, and the two APKs are compared.
plugins {
    id("com.android.application")
}

android {
    namespace = "org.ghost.spike.r8"
    compileSdk = 37

    defaultConfig {
        applicationId = "org.ghost.spike.r8"
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "s0"
    }

    flavorDimensions += "m"
    productFlavors {
        create("base") { dimension = "m" }
        create("media") { dimension = "m" }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }
}

dependencies {
    "mediaImplementation"("androidx.media3:media3-transformer:1.11.1")
    "mediaImplementation"("androidx.media3:media3-exoplayer:1.11.1")
    "mediaImplementation"("androidx.media3:media3-muxer:1.11.1")
    "mediaImplementation"("androidx.media3:media3-effect:1.11.1")
    "mediaImplementation"("androidx.media3:media3-common:1.11.1")
}

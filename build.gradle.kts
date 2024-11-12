@file:Suppress("UNUSED_VARIABLE")

plugins {
    kotlin("multiplatform") version "1.9.21"
    kotlin("plugin.serialization") version "2.0.0"
    `maven-publish`
}

group = "net.sergeych"
version = "1.3.1-SNAPSHOT"

repositories {
    mavenLocal()
    mavenCentral()
    maven("https://maven.universablockchain.com")
}

//configurations.all {
//    resolutionStrategy.cacheChangingModulesFor(30, "seconds")
//}

kotlin {
    jvm {
//        compilations.all {
//            kotlinOptions.jvmTarget = "1.8"
//        }
//        withJava()
//        testRuns["test"].executionTask.configure {
//            useJUnitPlatform()
//        }
    }
    js(IR) {
        browser {
            testTask {
//                useKarma {
//                    useChromeHeadless()
//                }
                useMocha {
                    timeout = "30000"
                }
            }
            commonWebpackConfig {
//                cssSupport.enabled = true
            }
        }
    }
//    val hostOs = System.getProperty("os.name")
//    val isMingwX64 = hostOs.startsWith("Windows")
//    val nativeTarget = when {
//        hostOs == "Mac OS X" -> macosX64("native")
//        hostOs == "Linux" -> linuxX64("native")
//        isMingwX64 -> mingwX64("native")
//        else -> throw GradleException("Host OS is not supported in Kotlin/Native.")
//    }

//    val publicationsFromMainHost =
//        listOf(jvm(), js()).map { it.name } + "kotlinMultiplatform"

    sourceSets {
        all {
            languageSettings.optIn("kotlin.ExperimentalUnsignedTypes")
            languageSettings.optIn("kotlinx.serialization.ExperimentalSerializationApi")
            languageSettings.optIn("kotlinx.coroutines.flow.DelicateCoroutinesApi")
        }
        val commonMain by getting {
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
                api("org.jetbrains.kotlinx:kotlinx-datetime:0.5.0")
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
                api("net.sergeych:boss-serialization-mp:[0.1.3-SNAPSHOT,)")
                api("net.sergeych:mp_stools:[1.3.2-SNAPSHOT,)")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation("com.icodici:crypto:3.14.6")
            }
        }
        val jvmTest by getting
        val jsMain by getting {
            dependencies {
                implementation(npm("unicrypto", "1.14.1"))
            }
        }
        val jsTest by getting {
            dependencies {
                implementation(kotlin("test-js"))
            }
        }
//        val nativeMain by getting
//        val nativeTest by getting
    }

    publishing {
        publications {

//            matching { it.name in publicationsFromMainHost }.all {
//                val targetPublication = this@all
//                tasks.withType<AbstractPublishToMaven>()
//                    .matching { it.publication == targetPublication }
//                    .configureEach { onlyIf { findProperty("isMainHost") == "true" } }
//            }

//            create<MavenPublication>("maven") {
//                from(components["java"])
//            }
        }
        repositories {
            maven {
                val mavenUser: String by project
                val mavenPassword: String by project
                url = uri("https://maven.universablockchain.com/")
                credentials {
                    username = mavenUser
                    password = mavenPassword
                }
            }
        }
    }
}

//afterEvaluate {
//    rootProject.extensions.configure<org.jetbrains.kotlin.gradle.targets.js.nodejs.NodeJsRootExtension> {
//        versions.webpackDevServer.version = "4.0.0"
//        versions.webpackCli.version = "4.9.0"
//    }
//}
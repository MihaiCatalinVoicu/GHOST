package org.ghost.network

import org.ghost.device.DeviceRunner
import java.util.Collections

/**
 * The PT-1 probe's instrumentation (Phase 12 §12.1 V-T6 re-run): the plain `DeviceRunner` over
 * the one device suite. JDK calls only in this file — the runner discipline of
 * `crypto-bridge`'s deviceRunner (the test APK may run against a shrunk Kotlin stdlib).
 */
class PtDeviceRunner : DeviceRunner(Collections.singletonList(PtInstallDeviceTest::class.java))

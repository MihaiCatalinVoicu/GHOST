package org.ghost.crypto.bridge;

/**
 * The probe's declaration of the channel surface (Phase 10 design §10.2, slice S2b): the same JNI
 * names and argument types as `:crypto-bridge`'s Kotlin `MlsNative`, so the device probe calls the
 * entry points the **shipped** `libghost_client_net.so` exports, on ART, through JNI — not a test
 * library and not a native executable. Only the functions the probe's rounds use are declared.
 *
 * Probe tooling only (`scripts/device/mls-probe.sh`): never compiled into an APK; the production
 * declaration is the Kotlin one, which G-M6 checks.
 */
public final class MlsNative {
    private MlsNative() {}

    public static native byte[] ctxOpen(byte[] stateKey);

    public static native byte[] ctxClose(long handle);

    public static native byte[] channelOpen(long handle, byte[] channelId, byte[] pseudonymSeed);

    public static native byte[] groupCreate(long handle, byte[] channelId, byte[] policy, int day);

    public static native byte[] keyPackage(long handle, byte[] channelId, int purpose, int day);

    public static native byte[] welcomeJoin(long handle, byte[] channelId, byte[] rows, byte[] welcomeBlob,
            int day, int expectedGeneration, byte[] expectedNs, int anchorKind, byte[] anchor);

    public static native byte[] receive(long handle, byte[] channelId, byte[] rows, long epoch, byte[] messages,
            int day);

    public static native byte[] settle(long handle, byte[] channelId, byte[] rows, int winnerKind, byte[] winner,
            int generation, int day);

    public static native byte[] commit(long handle, byte[] channelId, byte[] rows, byte[] request, int day);

    public static native byte[] encrypt(long handle, byte[] channelId, byte[] rows, byte[] content, int seq,
            int day);

    public static native byte[] inviteBuild(long handle, byte[] channelId, byte[] rows, byte[] gEnv,
            int generation, int expiryDay, int kdfCode, byte[] password, int carryName, int day);

    public static native byte[] inviteParse(long handle, byte[] invite, byte[] password, byte[] slots);

    public static native byte[] joinRequest(long handle, byte[] channelId, byte[] inviteId, byte[] inviteSeedEnv,
            byte[] keyPackage);

    public static native byte[] joinVerify(long handle, byte[] channelId, byte[] body, byte[] invitePk,
            byte[] member, int generation);

    public static native byte[] contentEncode(byte[] fields);

    public static native byte[] roster(long handle, byte[] channelId, byte[] rows, int day);
}

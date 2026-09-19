package org.ghost.dmspike;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * V-5: loads the host build of ghost-dm-spike (feature jni-host) from the path given as the first
 * argument, as DmNative would load ghost-dm-host through -Dghost.dm.native, and calls its JNI
 * exports. Exits 1 on any unexpected result.
 */
public final class DmHostProbe {
    static native byte[] olmRoundTrip(byte[] messagingBranch);
    static native byte[] xwingRoundTrip(byte[] seed);
    static native byte[] panicProbe(byte[] input);

    public static void main(String[] args) {
        System.load(args[0]);
        HexFormat hex = HexFormat.of();
        byte[] m = hex.parseHex("82453de069051555acf43dc3b93fa3be1a218d828bc156f7c1f4ad77a66f50cf");
        byte[] olm = olmRoundTrip(m);
        byte[] again = olmRoundTrip(m);
        String reply = new String(Arrays.copyOfRange(olm, 33, olm.length));
        boolean olmOk = olm[0] == 0 && reply.equals("hello from the JVM host build")
            && Arrays.equals(Arrays.copyOfRange(olm, 1, 33), Arrays.copyOfRange(again, 1, 33));
        System.out.println("V5 olmRoundTrip code=" + olm[0] + " identity=" + hex.formatHex(olm, 1, 33) + " reply=\"" + reply + "\"");
        byte[] seed = new byte[32];
        byte[] kem = xwingRoundTrip(seed);
        boolean kemOk = kem[0] == 0 && kem.length == 1 + 1216 + 1 && kem[kem.length - 1] == 1;
        System.out.println("V5 xwingRoundTrip code=" + kem[0] + " publicKeyLength=" + (kem.length - 2) + " secretsEqual=" + kem[kem.length - 1]);
        byte[] panic = panicProbe(new byte[100]);
        boolean panicOk = panic.length == 1 && (panic[0] & 0xff) == 0xff;
        System.out.println("V5 panicProbe code=" + (panic[0] & 0xff) + " (0xff = INTERNAL, the JVM survived)");
        System.out.println("V5 java.version=" + System.getProperty("java.version") + " os=" + System.getProperty("os.name") + " arch=" + System.getProperty("os.arch"));
        System.exit(olmOk && kemOk && panicOk ? 0 : 1);
    }
}

// Phase 11 S0 evidence tooling (not product code): an independent JDK implementation of the media
// object of docs/design/faza11-media.md §3.2-§3.6, §4.1 and §4.2, written from the design text,
// that replays ghost/spikes/media-s0/rust/vectors/media_object.txt. It shares no code with the Rust
// reference: JCA "ChaCha20-Poly1305" (SunJCE), HKDF written here from RFC 5869 over "HmacSHA256",
// and its own encoders of the manifest, descriptor, key_env and op_id.
//
// Run: java ghost/spikes/media-s0/jvm/MediaVectors.java ghost/spikes/media-s0/rust/vectors/media_object.txt
// Exit code 0 only if every recorded value is reproduced and every negative case is refused.

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MediaVectors {
    static final int FRAG = 65536, TAG = 16, CHUNK_CT = 4 * FRAG, CHUNK_PT = CHUNK_CT - TAG;
    static final int[] CLASSES = {16, 24, 36, 56, 84, 128, 192, 288, 432, 648, 804};
    static final long MAX_CONTENT = 52428800L;
    static final int MANIFEST_PT = FRAG - 32 - TAG, PREVIEW_OFFSET = 38, PREVIEW_MAX = 32768;
    static final int HASHES_OFFSET = PREVIEW_OFFSET + PREVIEW_MAX;

    static int compared = 0, equal = 0, negatives = 0, refused = 0, commitChecks = 0, commitDistinct = 0;
    static final List<String> failures = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        List<String> lines = Files.readAllLines(Path.of(args[0]), StandardCharsets.UTF_8);
        Map<String, Map<String, String>> sections = new LinkedHashMap<>();
        Map<String, String> cur = null;
        for (String l : lines) {
            if (l.startsWith("#") || l.isBlank()) continue;
            if (l.startsWith("[")) {
                cur = new LinkedHashMap<>();
                sections.put(l.substring(1, l.length() - 1), cur);
                continue;
            }
            int eq = l.indexOf(" = ");
            if (cur != null && eq > 0) cur.put(l.substring(0, eq), l.substring(eq + 3));
        }
        // Class boundaries.
        for (String l : lines) {
            if (!l.startsWith("boundary len = ")) continue;
            String[] p = l.split(" ");
            long len = Long.parseLong(p[3]);
            Integer cls = classFor(len);
            check("boundary " + len, p[6], cls == null ? "none" : cls.toString());
        }
        for (Map.Entry<String, Map<String, String>> e : sections.entrySet()) {
            if (e.getKey().startsWith("object ")) replay(e.getKey().substring(7), e.getValue());
        }
        System.out.println("media-vectors (JDK " + System.getProperty("java.version") + "): " + compared
                + " values compared, " + equal + " equal; " + negatives + " AEAD negative cases, " + refused + " refused; "
                + commitChecks + " commitment-separation checks, " + commitDistinct + " distinct");
        for (String f : failures) System.out.println("FAIL " + f);
        System.exit(failures.isEmpty() && compared == equal && negatives == refused && commitChecks == commitDistinct && compared > 0 ? 0 : 1);
    }

    static void replay(String name, Map<String, String> v) throws Exception {
        byte[] kf = unhex(v.get("k_f")), oid = unhex(v.get("object_id"));
        int kind = Integer.parseInt(v.get("kind")), flags = Integer.parseInt(v.get("flags"));
        byte[] content = recipe(v.get("content"));
        byte[] preview = recipe(v.get("preview"));
        check(name + " content_sha256", v.get("content_sha256"), hex(sha256(content)));
        byte[] prk = hmac(oid, kf);
        byte[] kp = hkdfExpand(prk, "ghost/v1/media/payload"), km = hkdfExpand(prk, "ghost/v1/media/manifest");
        byte[] commit = hkdfExpand(prk, "ghost/v1/media/commit");
        check(name + " k_p", v.get("k_p"), hex(kp));
        check(name + " k_m", v.get("k_m"), hex(km));
        check(name + " commit", v.get("commit"), hex(commit));
        int cls = classFor(content.length);
        check(name + " class_code", v.get("class_code"), Integer.toString(cls));
        int f = CLASSES[cls], n = f / 4;
        byte[] ad = cat("ghost/v1/media/ad/chunk".getBytes(StandardCharsets.US_ASCII), new byte[] {1}, oid, new byte[] {(byte) kind});
        check(name + " chunk_ad", v.get("chunk_ad"), hex(ad));
        byte[] padded = Arrays.copyOf(content, n * CHUNK_PT);
        List<byte[]> fragments = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            byte[] nonce = new byte[12];
            ByteBuffer.wrap(nonce, 7, 4).putInt(i);
            nonce[11] = (byte) (i == n - 1 ? 1 : 0);
            check(name + " chunk_nonce[" + i + "]", v.get("chunk_nonce[" + i + "]"), hex(nonce));
            byte[] ct = seal(kp, nonce, ad, Arrays.copyOfRange(padded, i * CHUNK_PT, (i + 1) * CHUNK_PT));
            for (int k = 0; k < 4; k++) fragments.add(Arrays.copyOfRange(ct, k * FRAG, (k + 1) * FRAG));
        }
        for (int j = 0; j < f; j++) check(name + " fragment_sha256[" + j + "]", v.get("fragment_sha256[" + j + "]"), hex(sha256(fragments.get(j))));
        // Manifest plaintext, written from the §3.5 table.
        ByteBuffer mp = ByteBuffer.allocate(MANIFEST_PT);
        mp.put((byte) 1).put((byte) kind).put((byte) flags).put((byte) cls).put(oid).putLong(content.length);
        mp.putShort((short) Integer.parseInt(v.get("width"))).putShort((short) Integer.parseInt(v.get("height")));
        mp.putInt(Integer.parseInt(v.get("duration_ms"))).putShort((short) preview.length).put(preview);
        mp.position(HASHES_OFFSET);
        for (byte[] frag : fragments) mp.put(sha256(frag));
        byte[] mpb = mp.array();
        check(name + " manifest_plaintext_head", v.get("manifest_plaintext_head"), hex(Arrays.copyOf(mpb, 38)));
        check(name + " manifest_plaintext_sha256", v.get("manifest_plaintext_sha256"), hex(sha256(mpb)));
        byte[] adm = cat("ghost/v1/media/ad/manifest".getBytes(StandardCharsets.US_ASCII), new byte[] {1}, oid, commit);
        check(name + " manifest_ad", v.get("manifest_ad"), hex(adm));
        byte[] blob = cat(commit, seal(km, new byte[12], adm, mpb));
        check(name + " manifest blob length", "65536", Integer.toString(blob.length));
        byte[] mh = sha256(blob);
        check(name + " manifest_hash", v.get("manifest_hash"), hex(mh));
        check(name + " manifest_blob_tail16", v.get("manifest_blob_tail16"), hex(Arrays.copyOfRange(blob, FRAG - 16, FRAG)));
        // Descriptor (§4.1).
        String caption = v.get("caption");
        byte[] cap = caption.substring(1, caption.length() - 1).getBytes(StandardCharsets.UTF_8);
        ByteBuffer d = ByteBuffer.allocate(86 + cap.length);
        d.put((byte) 1).put((byte) kind).put((byte) flags).put((byte) cls).put(oid).put(new byte[32]).put(mh);
        d.putShort((short) cap.length).put(cap);
        check(name + " descriptor", v.get("descriptor"), hex(d.array()));
        // key_env (§4.2): nonce || ChaCha20-Poly1305(state_key, nonce, "ghost/v1/wrap/media-file-key" || binding, K_f).
        byte[] sk = unhex(v.get("state_key")), dest = unhex(v.get("dest_id"));
        for (int role : new int[] {1, 2}) {
            // One fixed nonce per role: a vector set must not seal twice under one (key, nonce).
            byte[] wn = unhex(v.get(role == 1 ? "wrap_nonce_out" : "wrap_nonce_in"));
            byte[] bind = cat(new byte[] {(byte) role}, dest, oid, mh);
            byte[] wad = cat("ghost/v1/wrap/media-file-key".getBytes(StandardCharsets.US_ASCII), bind);
            byte[] env = cat(wn, seal(sk, wn, wad, kf));
            check(name + " key_env role " + role, v.get(role == 1 ? "key_env_out" : "key_env_in"), hex(env));
        }
        check(name + " op_id manifest", v.get("op_id[manifest,gen0,resend0]"), hex(opId(oid, -1, 0, 0)));
        check(name + " op_id 0/1/2", v.get("op_id[0,gen1,resend2]"), hex(opId(oid, 0, 1, 2)));
        // Negative cases, JDK side: a flipped fragment byte, the manifest under another object_id,
        // a key_env under the other role, another K_f's commitment.
        byte[] ct0 = cat(fragments.get(0), fragments.get(1), fragments.get(2), fragments.get(3));
        ct0[1234] ^= 1;
        byte[] n0 = new byte[12];
        n0[11] = (byte) (n == 1 ? 1 : 0);
        negative(name + " flipped chunk byte", kp, n0, ad, ct0);
        byte[] ct1 = cat(fragments.get(0), fragments.get(1), fragments.get(2), fragments.get(3));
        byte[] nLast = new byte[12];
        nLast[11] = 1;
        if (n > 1) negative(name + " chunk 0 opened as last", kp, nLast, ad, ct1);
        byte[] oid2 = oid.clone();
        oid2[0] ^= 1;
        byte[] adm2 = cat("ghost/v1/media/ad/manifest".getBytes(StandardCharsets.US_ASCII), new byte[] {1}, oid2, commit);
        negative(name + " manifest under another object_id", km, new byte[12], adm2, Arrays.copyOfRange(blob, 32, FRAG));
        byte[] envOut = unhex(v.get("key_env_out"));
        byte[] bindIn = cat(new byte[] {2}, dest, oid, mh);
        negative(name + " key_env_out under the in binding", sk, Arrays.copyOf(envOut, 12),
                cat("ghost/v1/wrap/media-file-key".getBytes(StandardCharsets.US_ASCII), bindIn), Arrays.copyOfRange(envOut, 12, 60));
        // Review H13 (2026-10-04): not an AEAD refusal. It checks only that another K_f derives
        // another commitment (the comparison a reader makes before opening the manifest), so it is
        // counted apart from the refusals above, which exercise ChaCha20-Poly1305's tag check.
        byte[] kf2 = kf.clone();
        kf2[31] ^= 1;
        commitChecks++;
        if (!Arrays.equals(hkdfExpand(hmac(oid, kf2), "ghost/v1/media/commit"), commit)) commitDistinct++;
        else failures.add(name + " another K_f gave the same commitment");
    }

    static Integer classFor(long len) {
        if (len == 0 || len > MAX_CONTENT) return null;
        for (int c = 0; c < CLASSES.length; c++) if ((long) (CLASSES[c] / 4) * CHUNK_PT >= len) return c;
        return null;
    }

    static byte[] opId(byte[] oid, int ordinal, int gen, int resend) throws Exception {
        byte[] in = cat("ghost/v1/media/op".getBytes(StandardCharsets.US_ASCII), oid,
                new byte[] {(byte) (ordinal >> 8), (byte) ordinal, (byte) gen, (byte) resend});
        return Arrays.copyOf(sha256(in), 16);
    }

    static byte[] recipe(String r) throws Exception {
        // sha256ctr("seed", len)
        int q1 = r.indexOf('"'), q2 = r.lastIndexOf('"');
        byte[] seed = r.substring(q1 + 1, q2).getBytes(StandardCharsets.UTF_8);
        int len = Integer.parseInt(r.substring(r.lastIndexOf(',') + 1, r.length() - 1).trim());
        ByteArrayOutputStream out = new ByteArrayOutputStream(len + 32);
        for (int i = 0; out.size() < len; i++) out.write(sha256(cat(seed, ByteBuffer.allocate(4).putInt(i).array())));
        return Arrays.copyOf(out.toByteArray(), len);
    }

    static byte[] seal(byte[] key, byte[] nonce, byte[] ad, byte[] pt) throws Exception {
        Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
        c.updateAAD(ad);
        return c.doFinal(pt);
    }

    static void negative(String what, byte[] key, byte[] nonce, byte[] ad, byte[] ct) throws Exception {
        negatives++;
        Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
        c.updateAAD(ad);
        try {
            c.doFinal(ct);
            failures.add(what + ": opened");
        } catch (AEADBadTagException expected) {
            refused++;
        }
    }

    static byte[] hmac(byte[] key, byte[] msg) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(key, "HmacSHA256"));
        return m.doFinal(msg);
    }

    /** RFC 5869 expand for L = 32: T(1) = HMAC(PRK, info || 0x01). */
    static byte[] hkdfExpand(byte[] prk, String info) throws Exception {
        return hmac(prk, cat(info.getBytes(StandardCharsets.US_ASCII), new byte[] {1}));
    }

    static byte[] sha256(byte[] b) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(b);
    }

    static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.writeBytes(p);
        return o.toByteArray();
    }

    static void check(String what, String expected, String actual) {
        compared++;
        if (expected != null && expected.equals(actual)) equal++;
        else failures.add(what + ": expected " + expected + " got " + actual);
    }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }

    static byte[] unhex(String h) {
        byte[] o = new byte[h.length() / 2];
        for (int i = 0; i < o.length; i++) o[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        return o;
    }
}

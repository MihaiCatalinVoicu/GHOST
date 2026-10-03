package org.ghost.device;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.ghost.crypto.bridge.MlsNative;

/**
 * The successor of S0's `device_probe` (Phase 10 design §12.11, §19.29.3 R-21, §14 S2 exit; slice
 * S2b): run on Android's ART with `app_process`, it loads the **shipped** `libghost_client_net.so`
 * and drives the closed channel surface through JNI, timing what the S2 exit names:
 *
 * <ul>
 *   <li>{@code argon2 N}: the invite's Argon2id profile (kdf_code 1: m = 64 MiB, t = 1, p = 4) —
 *       {@code inviteBuild} and {@code inviteParse} of a password invite, each of which runs it once,
 *       N times each; the open invite's parse (no Argon2id) for comparison; the process's peak RSS
 *       ({@code VmHWM}) before the first Argon2id call and after the last;</li>
 *   <li>{@code round N}: N three-member rounds (create; two open invites, each parsed, a KeyPackage,
 *       a join request, its verification; one commit adding both; the owner's settle; both joins from
 *       the Welcome blobs; a post encrypted by the owner and received by both), each step timed, the
 *       three members' epoch authenticators compared.</li>
 * </ul>
 *
 * Medians are printed (one line per measurement, {@code key value}); the probe exits non-zero when
 * any call is refused or the members disagree. Probe tooling only (never in an APK).
 */
public final class MlsProbe {
    private static final int DAY = 20_725;

    public static void main(String[] args) throws Exception {
        String mode = args.length > 0 ? args[0] : "round";
        int n = args.length > 1 ? Integer.parseInt(args[1]) : 5;
        String lib = args.length > 2 ? args[2] : "/data/local/tmp/mls-probe/libghost_client_net.so";
        long beforeLoad = hwm();
        long t0 = System.nanoTime();
        System.load(lib);
        out("load_ms", ms(t0));
        out("vmhwm_before_load_kib", beforeLoad);
        out("vmhwm_after_load_kib", hwm());
        out("abi", System.getProperty("os.arch"));
        if (mode.equals("argon2")) {
            argon2(n);
        } else {
            round(n);
        }
        out("vmhwm_end_kib", hwm());
        out("vmrss_end_kib", status("VmRSS:"));
        System.out.println("probe_ok " + mode);
    }

    // ---- the Argon2id profile ---------------------------------------------------------------------

    static void argon2(int n) {
        Member a = new Member(1);
        byte[] channel = id(0x10);
        a.open(channel);
        // A password channel (flag bit 2, pw_version 1; members may not invite, Q46 (b)).
        Rec created = ok(MlsNative.groupCreate(a.h, channel, policy(channel, a.p, 4, 1), DAY), "groupCreate");
        a.apply(created);
        byte[] gEnv = created.get(0x0e);
        byte[] password = "cabin frost ladder margin orbit".getBytes(StandardCharsets.UTF_8);
        long baseline = hwm();
        out("vmhwm_before_argon2_kib", baseline);
        double[] build = new double[n];
        double[] parse = new double[n];
        double[] wrong = new double[n];
        byte[] invite = null;
        for (int i = 0; i < n; i++) {
            long t = System.nanoTime();
            Rec built = ok(MlsNative.inviteBuild(a.h, channel, a.rows(), gEnv, 0, DAY + 7, 1, password.clone(), 0, DAY),
                    "inviteBuild(password)");
            build[i] = ms(t);
            invite = built.get(0x6b);
            Member b = new Member(100 + i);
            t = System.nanoTime();
            ok(MlsNative.inviteParse(b.h, invite, password.clone(), new byte[0]), "inviteParse(password)");
            parse[i] = ms(t);
            t = System.nanoTime();
            byte[] refused = MlsNative.inviteParse(b.h, invite, "cabin frost".getBytes(StandardCharsets.UTF_8), new byte[0]);
            wrong[i] = ms(t);
            if (refused == null || refused[0] != 21) throw new IllegalStateException("a wrong password must be WRONG_PASSWORD");
            b.close();
        }
        long peak = hwm();
        out("vmhwm_after_argon2_kib", peak);
        out("vmhwm_argon2_delta_kib", peak - baseline);
        out("argon2_invite_build_ms_median", median(build));
        out("argon2_invite_parse_ms_median", median(parse));
        out("argon2_wrong_password_ms_median", median(wrong));
        out("argon2_invite_parse_ms_min", min(parse));
        out("argon2_invite_parse_ms_max", max(parse));
        out("argon2_runs", n);
        // The open invite's parse, which runs no Argon2id (its key derives from the printed salt).
        byte[] open = id(0x11);
        a.open(open);
        Rec openCreated = ok(MlsNative.groupCreate(a.h, open, policy(open, a.p, 1, 0), DAY), "groupCreate(open)");
        Member o = new Member(99);
        double[] openParse = new double[n];
        Map<String, byte[][]> openRows = new LinkedHashMap<>();
        applyTo(openRows, openCreated);
        for (int i = 0; i < n; i++) {
            byte[] inv = ok(MlsNative.inviteBuild(a.h, open, encodeRows(openRows), openCreated.get(0x0e), 0, DAY + 7, 0, null, 0, DAY),
                    "inviteBuild(open)").get(0x6b);
            long t = System.nanoTime();
            ok(MlsNative.inviteParse(o.h, inv, null, new byte[0]), "inviteParse(open)");
            openParse[i] = ms(t);
        }
        out("open_invite_parse_ms_median", median(openParse));
        o.close();
        a.close();
    }

    // ---- the three-member round -------------------------------------------------------------------

    static void round(int n) {
        String[] steps = {"create", "invite_build", "invite_parse", "key_package", "join_request", "join_verify",
            "commit_2_adds", "settle_own", "welcome_join", "post_encrypt", "post_receive", "round_total"};
        Map<String, double[]> times = new LinkedHashMap<>();
        for (String s : steps) times.put(s, new double[n]);
        for (int r = 0; r < n; r++) {
            long start = System.nanoTime();
            byte[] channel = id(0x20 + r);
            Member a = new Member(10 * r + 1);
            Member b = new Member(10 * r + 2);
            Member c = new Member(10 * r + 3);
            a.open(channel);
            b.open(channel);
            c.open(channel);
            long t = System.nanoTime();
            Rec created = ok(MlsNative.groupCreate(a.h, channel, policy(channel, a.p, 1, 0), DAY), "groupCreate");
            times.get("create")[r] = ms(t);
            a.apply(created);
            byte[] gEnv = created.get(0x0e);
            byte[] jkEnv = created.get(0x10);
            Tlv request = new Tlv();
            Map<Member, Rec> parsed = new LinkedHashMap<>();
            for (Member j : new Member[] {b, c}) {
                t = System.nanoTime();
                Rec built = ok(MlsNative.inviteBuild(a.h, channel, a.rows(), gEnv, 0, DAY + 7, 0, null, 0, DAY), "inviteBuild");
                times.get("invite_build")[r] += ms(t) / 2;
                t = System.nanoTime();
                Rec p = ok(MlsNative.inviteParse(j.h, built.get(0x6b), null, new byte[] {0}), "inviteParse");
                times.get("invite_parse")[r] += ms(t) / 2;
                parsed.put(j, p);
                t = System.nanoTime();
                Rec kp = ok(MlsNative.keyPackage(j.h, channel, 1, DAY), "keyPackage");
                times.get("key_package")[r] += ms(t) / 2;
                j.apply(kp);
                t = System.nanoTime();
                byte[] body = ok(MlsNative.joinRequest(j.h, channel, p.get(0x4d), p.get(0x70), kp.get(0x1a)), "joinRequest").get(0x66);
                times.get("join_request")[r] += ms(t) / 2;
                t = System.nanoTime();
                Rec v = ok(MlsNative.joinVerify(a.h, channel, body, built.get(0x4e), new byte[0], 0), "joinVerify");
                times.get("join_verify")[r] += ms(t) / 2;
                Tlv evidence = new Tlv().put(0x1b, v.get(0x1b)).put(0x4d, built.get(0x4d)).put(0x4e, built.get(0x4e))
                        .put(0x4f, built.get(0x4f)).put(0x50, a.p).put(0x51, built.get(0x51)).put(0x52, v.get(0x52));
                request.record(0x3e, new Tlv().put(0x1a, v.get(0x1a)).record(0x3c, evidence));
            }
            request.u8(0x3b, 0).u32(0x3a, DAY * 1440L).u32(0x5d, 4096).u32(0x0c, 0).u64(0x0d, 0).put(0x0e, gEnv);
            t = System.nanoTime();
            Rec committed = ok(MlsNative.commit(a.h, channel, a.rows(), request.bytes(), DAY), "commit");
            times.get("commit_2_adds")[r] = ms(t);
            a.apply(committed);
            t = System.nanoTime();
            Rec settled = ok(MlsNative.settle(a.h, channel, a.rows(), 2, committed.get(0x56), 0, DAY), "settle(own)");
            times.get("settle_own")[r] = ms(t);
            a.apply(settled);
            byte[] authenticator = settled.get(0x0b);
            List<byte[]> welcomes = committed.all(0x57);
            int k = 0;
            for (Member j : new Member[] {b, c}) {
                Rec p = parsed.get(j);
                t = System.nanoTime();
                Rec joined = ok(MlsNative.welcomeJoin(j.h, channel, j.rows(), welcomes.get(k++), DAY, 0, p.get(0x0f), 1, p.get(0x6f)),
                        "welcomeJoin");
                times.get("welcome_join")[r] += ms(t) / 2;
                j.apply(joined);
                if (!Arrays.equals(authenticator, joined.get(0x0b))) throw new IllegalStateException("epoch authenticators differ");
            }
            Tlv content = new Tlv().u8(0x72, 1).put(0x73, new byte[16]).u32(0x74, DAY * 1440L + 1).u8(0x1f, 4)
                    .put(0x75, "salut, canal".getBytes(StandardCharsets.UTF_8));
            t = System.nanoTime();
            byte[] encoded = ok(MlsNative.contentEncode(content.bytes()), "contentEncode").get(0x7e);
            Rec encrypted = ok(MlsNative.encrypt(a.h, channel, a.rows(), encoded, 1, DAY), "encrypt");
            times.get("post_encrypt")[r] = ms(t);
            a.apply(encrypted);
            for (Member j : new Member[] {b, c}) {
                t = System.nanoTime();
                Rec received = ok(MlsNative.receive(j.h, channel, j.rows(), 1, new Tlv().put(0x2c, encrypted.get(0x56)).bytes(), DAY),
                        "receive");
                times.get("post_receive")[r] += ms(t) / 2;
                j.apply(received);
                Rec item = received.record(0x2d);
                if (item.u8(0x2e) != 1) throw new IllegalStateException("the post did not decrypt");
                if (!Arrays.equals(a.p, item.get(0x30))) throw new IllegalStateException("wrong author");
            }
            times.get("round_total")[r] = ms(start);
            a.close();
            b.close();
            c.close();
        }
        for (Map.Entry<String, double[]> e : times.entrySet()) out(e.getKey() + "_ms_median", median(e.getValue()));
        out("rounds", n);
    }

    // ---- a member ------------------------------------------------------------------------------------

    static final class Member {
        final long h;
        byte[] p;
        final Map<String, byte[][]> rows = new LinkedHashMap<>();
        final int index;

        Member(int index) {
            this.index = index;
            byte[] key = new byte[32];
            for (int i = 0; i < 32; i++) key[i] = (byte) (index * 7 + i);
            h = u64(ok(MlsNative.ctxOpen(key), "ctxOpen").get(0x01));
        }

        void open(byte[] channel) {
            byte[] seed = new byte[32];
            for (int i = 0; i < 32; i++) seed[i] = (byte) (index * 31 + i + 1);
            p = ok(MlsNative.channelOpen(h, channel, seed), "channelOpen").get(0x02);
        }

        void apply(Rec reply) {
            applyTo(rows, reply);
        }

        byte[] rows() {
            return encodeRows(rows);
        }

        void close() {
            ok(MlsNative.ctxClose(h), "ctxClose");
        }
    }

    static void applyTo(Map<String, byte[][]> rows, Rec reply) {
        for (Rec change : reply.records(0x03)) {
            byte[] scope = change.get(0x05);
            byte[] key = change.get(0x06);
            String k = scope[0] + ":" + hex(key);
            byte[] env = change.getOrNull(0x07);
            if (env == null) rows.remove(k); else rows.put(k, new byte[][] {scope, key, env});
        }
    }

    static byte[] encodeRows(Map<String, byte[][]> rows) {
        Tlv list = new Tlv();
        for (byte[][] row : rows.values()) list.record(0x04, new Tlv().put(0x05, row[0]).put(0x06, row[1]).put(0x07, row[2]));
        return list.bytes();
    }

    static byte[] policy(byte[] channel, byte[] owner, int flags, int pwVersion) {
        return new Tlv().put(0x1d, channel).u8(0x1e, 0).u8(0x1f, 4).u16(0x20, 0).u8(0x21, 0).u8(0x22, flags)
                .u16(0x23, 63).u16(0x24, pwVersion).put(0x25, new byte[0]).put(0x26, owner).put(0x27, owner).bytes();
    }

    // ---- the wire: code(1) || (tag(1) || len(u32 BE) || value)* ------------------------------------

    static final class Tlv {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        Tlv put(int tag, byte[] value) {
            out.write(tag);
            out.write(value.length >>> 24);
            out.write(value.length >>> 16);
            out.write(value.length >>> 8);
            out.write(value.length);
            out.write(value, 0, value.length);
            return this;
        }

        Tlv u8(int tag, int v) {
            return put(tag, new byte[] {(byte) v});
        }

        Tlv u16(int tag, int v) {
            return put(tag, new byte[] {(byte) (v >>> 8), (byte) v});
        }

        Tlv u32(int tag, long v) {
            return put(tag, new byte[] {(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v});
        }

        Tlv u64(int tag, long v) {
            byte[] b = new byte[8];
            for (int i = 0; i < 8; i++) b[i] = (byte) (v >>> (56 - 8 * i));
            return put(tag, b);
        }

        Tlv record(int tag, Tlv record) {
            return put(tag, record.bytes());
        }

        byte[] bytes() {
            return out.toByteArray();
        }
    }

    static final class Rec {
        final List<Integer> tags = new ArrayList<>();
        final List<byte[]> values = new ArrayList<>();

        static Rec parse(byte[] b, int from, int to) {
            Rec r = new Rec();
            int at = from;
            while (at < to) {
                int tag = b[at] & 0xff;
                int len = ((b[at + 1] & 0xff) << 24) | ((b[at + 2] & 0xff) << 16) | ((b[at + 3] & 0xff) << 8) | (b[at + 4] & 0xff);
                at += 5;
                r.tags.add(tag);
                r.values.add(Arrays.copyOfRange(b, at, at + len));
                at += len;
            }
            return r;
        }

        byte[] getOrNull(int tag) {
            int i = tags.indexOf(tag);
            return i < 0 ? null : values.get(i);
        }

        byte[] get(int tag) {
            byte[] v = getOrNull(tag);
            if (v == null) throw new IllegalStateException("missing field 0x" + Integer.toHexString(tag));
            return v;
        }

        List<byte[]> all(int tag) {
            List<byte[]> out = new ArrayList<>();
            for (int i = 0; i < tags.size(); i++) if (tags.get(i) == tag) out.add(values.get(i));
            return out;
        }

        Rec record(int tag) {
            byte[] v = get(tag);
            return parse(v, 0, v.length);
        }

        List<Rec> records(int tag) {
            List<Rec> out = new ArrayList<>();
            for (byte[] v : all(tag)) out.add(parse(v, 0, v.length));
            return out;
        }

        int u8(int tag) {
            return get(tag)[0] & 0xff;
        }
    }

    static Rec ok(byte[] reply, String what) {
        if (reply == null || reply.length == 0) throw new IllegalStateException(what + ": no reply (INTERNAL)");
        if (reply[0] != 0) throw new IllegalStateException(what + ": refused with code " + (reply[0] & 0xff));
        return Rec.parse(reply, 1, reply.length);
    }

    // ---- helpers ---------------------------------------------------------------------------------------

    static byte[] id(int seed) {
        byte[] b = new byte[32];
        for (int i = 0; i < 32; i++) b[i] = (byte) (seed + 3 * i);
        return b;
    }

    static long u64(byte[] b) {
        long v = 0;
        for (byte x : b) v = (v << 8) | (x & 0xff);
        return v;
    }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }

    static double ms(long since) {
        return (System.nanoTime() - since) / 1e6;
    }

    static double median(double[] v) {
        double[] s = v.clone();
        Arrays.sort(s);
        return s.length % 2 == 1 ? s[s.length / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
    }

    static double min(double[] v) {
        double m = Double.MAX_VALUE;
        for (double x : v) m = Math.min(m, x);
        return m;
    }

    static double max(double[] v) {
        double m = 0;
        for (double x : v) m = Math.max(m, x);
        return m;
    }

    static long hwm() {
        return status("VmHWM:");
    }

    static long status(String key) {
        try {
            for (String line : Files.readAllLines(new File("/proc/self/status").toPath())) {
                if (line.startsWith(key)) return Long.parseLong(line.substring(key.length()).trim().split("\\s+")[0]);
            }
        } catch (Exception e) {
            return -1;
        }
        return -1;
    }

    static void out(String key, Object value) {
        System.out.println(key + " " + (value instanceof Double ? String.format("%.2f", (Double) value) : value));
    }
}

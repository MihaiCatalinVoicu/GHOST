import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * V-14 (JDK half): replays vectors/ed25519-v14.txt with BouncyCastle through the code path of
 * :identity's Ed25519KeyPair (sign from a 32-byte seed; verify with length checks and
 * IllegalArgumentException mapped to false). Prints one line per verify case and exits 1 if a
 * signature differs or a verification result differs from ed25519-dalek's verify_strict.
 */
public final class Ed25519Equivalence {
    private static final HexFormat HEX = HexFormat.of();

    private static byte[] bytes(String field) {
        return "-".equals(field) ? new byte[0] : HEX.parseHex(field);
    }

    /** Ed25519KeyPair.verify, verbatim in behaviour. */
    static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        if (publicKey.length != 32 || signature.length != 64) return false;
        try {
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, new Ed25519PublicKeyParameters(publicKey, 0));
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(signature);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public static void main(String[] args) throws Exception {
        List<String> lines = Files.readAllLines(Path.of(args[0]));
        int signed = 0;
        int verified = 0;
        List<String> failures = new ArrayList<>();
        List<String> legacyOnly = new ArrayList<>();
        for (String line : lines) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] f = line.trim().split(" ");
            if ("sign".equals(f[0])) {
                byte[] seed = bytes(f[1]);
                byte[] message = bytes(f[2]);
                Ed25519PrivateKeyParameters key = new Ed25519PrivateKeyParameters(seed, 0);
                Ed25519Signer signer = new Ed25519Signer();
                signer.init(true, key);
                signer.update(message, 0, message.length);
                byte[] signature = signer.generateSignature();
                byte[] publicKey = key.generatePublicKey().getEncoded();
                if (!Arrays.equals(publicKey, bytes(f[3]))) failures.add("public key differs for seed " + f[1]);
                if (!Arrays.equals(signature, bytes(f[4]))) failures.add("signature differs for seed " + f[1]);
                if (!verify(publicKey, message, signature)) failures.add("own signature rejected for seed " + f[1]);
                signed++;
            } else if ("verify".equals(f[0])) {
                boolean bc = verify(bytes(f[2]), bytes(f[3]), bytes(f[4]));
                boolean strict = "1".equals(f[5]);
                boolean legacy = "1".equals(f[6]);
                System.out.printf("V14 %-26s bc=%d dalek-strict=%d dalek-legacy=%d %s%n", f[1], bc ? 1 : 0, strict ? 1 : 0,
                    legacy ? 1 : 0, bc == strict ? "same" : "DIFFERENT");
                if (bc != strict) failures.add("verify " + f[1] + ": bc=" + bc + " dalek-strict=" + strict);
                if (bc == legacy && bc != strict) legacyOnly.add(f[1]);
                verified++;
            }
        }
        System.out.printf("V14 summary: %d sign cases, %d verify cases, %d differences%n", signed, verified, failures.size());
        for (String failure : failures) System.out.println("V14 difference: " + failure);
        if (!legacyOnly.isEmpty()) System.out.println("V14 cases where BouncyCastle matches dalek's legacy verify instead: " + legacyOnly);
        System.exit(failures.isEmpty() ? 0 : 1);
    }
}

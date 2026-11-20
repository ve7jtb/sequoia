package dev.hybridmail;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;

/** Independent PQ Mail/Bouncy Castle half of the Sequoia integration test.
 * Uses only a public certificate and synthetic data: no account, identity
 * password, PIN, PKCS#11 operation, or token write is available in this class.
 */
public final class PqMailInterop {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("prepare|verify CERT OUTPUT");
        MailEngine.init(); // Registers the existing cryptographic providers only.
        var cert = new OpenPgp.PublicIdentity(Files.readAllBytes(Path.of(args[1])));
        var out = Path.of(args[2]);
        OpenPgp.check(cert.v6 != null && cert.v6.recipient.getAlgorithm() == 35,
                      "Expected a v6 ML-KEM-768 + X25519 recipient");
        if (args[0].equals("prepare")) {
            // Keep this MIME entity byte-identical to piv-test's synthetic
            // message. Cross-implementation decryption compares every octet.
            byte[] text = ("Content-Type: text/plain; charset=utf-8\r\n"
                + "Content-Transfer-Encoding: 7bit\r\n\r\n"
                + "Synthetic Sequoia YubiKey Level 3 interoperability test.\r\n")
                .getBytes(StandardCharsets.UTF_8);
            // Literal packet: binary format, empty filename, zero timestamp.
            // Encryption uses the app's public-key selection and AEAD path.
            byte[] literal = OpenPgp.frame(11, OpenPgp.cat(OpenPgp.b(98, 0), OpenPgp.n(0, 4), text));
            Files.write(out.resolve("pqmail-encrypted.pgp"), OpenPgp.encrypt(literal, cert));
            System.out.println("PASS PQ Mail prepared hybrid encrypted fixture (public operations only)");
        } else if (args[0].equals("verify")) {
            // The app checks certificate bindings, signing flags, expiry, the
            // v6 issuer fingerprint, and BOTH hybrid signature components.
            cert.v6.verify(Files.readAllBytes(out.resolve("signature.pgp")),
                           Files.readAllBytes(out.resolve("message.mime")));
            Files.writeString(out.resolve("pqmail-verification.txt"),
                "PASS PQ Mail/Bouncy Castle verifies Sequoia/PIV hybrid signature\n");
            System.out.println("PASS PQ Mail/Bouncy Castle verifies Sequoia/PIV hybrid signature");
        } else throw new IllegalArgumentException("Unknown test operation");
    }
}

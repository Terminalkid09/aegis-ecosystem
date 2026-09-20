package com.aegis.guard.security;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Identità device dell'agente (gap-closing mTLS nativo).
 *
 * <p>La chiave nasce LOCALMENTE (EC P-256, mai trasmessa); solo la CSR
 * (PKCS#10, CN = agent_id) va al server. Chiave e certificato vivono in
 * PEM separati ({@code device.key}/{@code device.crt}) con permessi 600:
 * niente password KDF (Java e Python usano encoding diversi per PKCS#12
 * e l'interop si rompe in silenzio) — la protezione è a livello file,
 * coerente con secret.json e spool. File corrotti → quarantena
 * {@code .bad}, mai cancellazione silenziosa. Fail-closed ovunque.
 */
public final class DeviceIdentity {

    private static final Logger log = LoggerFactory.getLogger(DeviceIdentity.class);

    public static final String KEY_FILE = "device.key";
    public static final String CRT_FILE = "device.crt";
    /** Legacy PKCS#12 (prime versioni): migrato automaticamente a PEM. */
    static final String LEGACY_STORE_FILE = "device.p12";
    public static final int RENEW_DAYS = 30;

    private DeviceIdentity() {}

    /** Password keystore derivata dal secret (mai persistita altrove). */
    public static char[] deriveStorePassword(String deviceSecret) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update("aegis-device-p12-v1|".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            sha.update(deviceSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(sha.digest()).toCharArray();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Genera EC P-256 (stdlib JCA, niente dipendenze per la chiave). */
    public static KeyPair generateKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return gen.generateKeyPair();
    }

    /** CSR PKCS#10 PEM con CN=agent_id (BouncyCastle solo per l'ASN.1). */
    public static String buildCsrPem(java.security.PublicKey pub,
            java.security.PrivateKey priv, String agentId) throws Exception {
        JcaPKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=" + agentId), pub);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(priv);
        PKCS10CertificationRequest csr = builder.build(signer);
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(csr.getEncoded());
        return "-----BEGIN CERTIFICATE REQUEST-----\n" + b64 + "\n-----END CERTIFICATE REQUEST-----\n";
    }

    /** Rinnovo quando scade entro N giorni (o già scaduto). Puro. */
    public static boolean needsRenewal(X509Certificate cert, int days) {
        if (cert == null) return true;
        try {
            Date limit = Date.from(Instant.now().plus(days, ChronoUnit.DAYS));
            return !cert.getNotAfter().after(limit);
        } catch (Exception e) {
            return true;
        }
    }

    public static boolean needsRenewal(X509Certificate cert) {
        return needsRenewal(cert, RENEW_DAYS);
    }

    /** Salva chiave+cert in PEM separati con 600 best-effort. */
    public static void store(Path dir, PrivateKey key, X509Certificate[] chain) throws Exception {
        Files.createDirectories(dir);
        String keyPem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(key.getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        StringBuilder certs = new StringBuilder();
        for (X509Certificate c : chain) {
            certs.append(certToPem(c));
        }
        Path keyTmp = dir.resolve(KEY_FILE + ".tmp");
        Path crtTmp = dir.resolve(CRT_FILE + ".tmp");
        Files.writeString(keyTmp, keyPem, java.nio.charset.StandardCharsets.UTF_8);
        Files.writeString(crtTmp, certs.toString(), java.nio.charset.StandardCharsets.UTF_8);
        bestEffortPrivate(keyTmp);
        bestEffortPrivate(crtTmp);
        Files.move(keyTmp, dir.resolve(KEY_FILE), StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE);
        Files.move(crtTmp, dir.resolve(CRT_FILE), StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE);
        bestEffortPrivate(dir.resolve(KEY_FILE));
        bestEffortPrivate(dir.resolve(CRT_FILE));
    }

    /**
     * Carica identità o null (assente/corrotto → quarantena .bad, mai throw).
     * Un eventuale legacy device.p12 viene migrato: se leggibile con la
     * password derivata si converte in PEM, altrimenti quarantena.
     */
    public static LoadedIdentity load(Path dir, char[] password) {
        migrateLegacy(dir, password);
        Path keyPath = dir.resolve(KEY_FILE);
        Path crtPath = dir.resolve(CRT_FILE);
        if (!Files.isRegularFile(keyPath) || !Files.isRegularFile(crtPath)) return null;
        try {
            byte[] keyDer = pemDecode(Files.readString(keyPath,
                    java.nio.charset.StandardCharsets.UTF_8), "PRIVATE KEY");
            PrivateKey key = java.security.KeyFactory.getInstance("EC")
                    .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(keyDer));
            java.util.List<X509Certificate> chain = new java.util.ArrayList<>();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (String pem : splitPemChain(Files.readString(crtPath,
                    java.nio.charset.StandardCharsets.UTF_8))) {
                try (InputStream in = new java.io.ByteArrayInputStream(
                        pem.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
                    chain.add((X509Certificate) cf.generateCertificate(in));
                }
            }
            if (chain.isEmpty()) throw new IllegalArgumentException("nessun certificato");
            return new LoadedIdentity(key, chain.toArray(new X509Certificate[0]));
        } catch (Exception e) {
            log.warn("Identità illeggibile ({}): quarantena, bootstrap da rifare",
                    e.getMessage());
            quarantine(keyPath);
            quarantine(crtPath);
            return null;
        }
    }

    /** Migra device.p12 legacy in PEM (best-effort, mai throw). */
    static void migrateLegacy(Path dir, char[] password) {
        Path legacy = dir.resolve(LEGACY_STORE_FILE);
        if (!Files.isRegularFile(legacy)) return;
        try (InputStream in = Files.newInputStream(legacy)) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(in, password);
            java.security.Key key = ks.getKey("device", password);
            java.security.cert.Certificate[] chain = ks.getCertificateChain("device");
            if (key instanceof PrivateKey && chain != null && chain.length > 0) {
                X509Certificate[] xchain = new X509Certificate[chain.length];
                for (int i = 0; i < chain.length; i++) xchain[i] = (X509Certificate) chain[i];
                store(dir, (PrivateKey) key, xchain);
                log.info("Identità migrata da PKCS#12 a PEM");
            }
            quarantine(legacy);
        } catch (Exception e) {
            log.warn("Legacy PKCS#12 non migrabile ({}): quarantena", e.getMessage());
            quarantine(legacy);
        }
    }

    static byte[] pemDecode(String pem, String label) throws Exception {
        String compact = pem.replace("-----BEGIN " + label + "-----", "")
                .replace("-----END " + label + "-----", "")
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(compact);
    }

    static java.util.List<String> splitPemChain(String bundle) {
        java.util.List<String> out = new java.util.ArrayList<>();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                java.util.regex.Pattern.DOTALL).matcher(bundle);
        while (m.find()) {
            out.add(m.group(0));
        }
        return out;
    }

    /** Identità caricata: chiave + catena (leaf in [0]). */
    public record LoadedIdentity(PrivateKey key, X509Certificate[] chain) {
        public X509Certificate leaf() {
            return chain[0];
        }
    }

    public static X509Certificate parseCertPem(String pem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream in = new java.io.ByteArrayInputStream(
                pem.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            return (X509Certificate) cf.generateCertificate(in);
        }
    }

    public static String certToPem(X509Certificate cert) throws Exception {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'})
                .encodeToString(cert.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
    }

    public static String fingerprintSha256(X509Certificate cert) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        return HexFormat.of().formatHex(sha.digest(cert.getEncoded()));
    }

    private static void quarantine(Path dst) {
        try {
            Files.move(dst, dst.resolveSibling(
                    dst.getFileName().toString() + ".bad-" + System.currentTimeMillis()),
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception ignored) {
        }
    }

    private static void bestEffortPrivate(Path p) {
        try {
            Set<PosixFilePermission> perms = EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(p, perms);
        } catch (Exception ignored) {
            // Windows/non-POSIX: ACL di default.
        }
    }
}

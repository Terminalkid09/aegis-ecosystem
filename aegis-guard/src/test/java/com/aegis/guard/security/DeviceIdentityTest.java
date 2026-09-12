package com.aegis.guard.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DeviceIdentityTest {

    @Test
    void keygenCsrRoundTrip() throws Exception {
        KeyPair kp = DeviceIdentity.generateKey();
        assertNotNull(kp.getPrivate());
        String pem = DeviceIdentity.buildCsrPem(kp.getPublic(), kp.getPrivate(), "agent-1");
        assertTrue(pem.contains("BEGIN CERTIFICATE REQUEST"));
        // La CSR si riparsa e la firma verifica con la chiave generata.
        byte[] der = java.util.Base64.getMimeDecoder().decode(
                pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s+", ""));
        PKCS10CertificationRequest parsed = new PKCS10CertificationRequest(der);
        JcaPKCS10CertificationRequest jca = new JcaPKCS10CertificationRequest(parsed);
        assertEquals("CN=agent-1", jca.getSubject().toString());
        assertTrue(jca.isSignatureValid(
                new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                        .build(kp.getPublic())));
    }

    @Test
    void storeLoadRoundTrip() throws Exception {
        Path dir = Files.createTempDirectory("identity");
        char[] pw = DeviceIdentity.deriveStorePassword("secret-xyz");
        KeyPair kp = DeviceIdentity.generateKey();
        // Self-signed finto per il roundtrip (firma non verificata qui).
        X509Certificate self = selfSigned(kp, "CN=agent-1");
        DeviceIdentity.store(dir, kp.getPrivate(), new X509Certificate[]{self});
        assertTrue(Files.exists(dir.resolve("device.key")));
        assertTrue(Files.exists(dir.resolve("device.crt")));
        DeviceIdentity.LoadedIdentity loaded = DeviceIdentity.load(dir, pw);
        assertNotNull(loaded);
        assertEquals(self, loaded.leaf());
        assertFalse(DeviceIdentity.needsRenewal(loaded.leaf()));
    }

    @Test
    void corruptQuarantines() throws Exception {
        Path dir = Files.createTempDirectory("identity-bad");
        char[] pw = DeviceIdentity.deriveStorePassword("secret-xyz");
        Files.writeString(dir.resolve("device.key"), "NOT-A-KEY");
        Files.writeString(dir.resolve("device.crt"), "NOT-A-CERT");
        assertNull(DeviceIdentity.load(dir, pw));
        assertFalse(Files.exists(dir.resolve("device.key")));
        assertFalse(Files.exists(dir.resolve("device.crt")));
        assertEquals(2, Files.list(dir)
                .filter(p -> p.getFileName().toString().contains(".bad-"))
                .count(), "file corrotti in quarantena, mai cancellati");
    }

    @Test
    void renewalPredicate() throws Exception {
        KeyPair kp = DeviceIdentity.generateKey();
        X509Certificate fresh = selfSigned(kp, "CN=x", 365);
        assertFalse(DeviceIdentity.needsRenewal(fresh));
        X509Certificate soon = selfSigned(kp, "CN=x", 10);
        assertTrue(DeviceIdentity.needsRenewal(soon));
        assertTrue(DeviceIdentity.needsRenewal(null));
    }

    @Test
    void fingerprintStable() throws Exception {
        KeyPair kp = DeviceIdentity.generateKey();
        X509Certificate c = selfSigned(kp, "CN=x");
        assertEquals(64, DeviceIdentity.fingerprintSha256(c).length());
        assertEquals(DeviceIdentity.fingerprintSha256(c), DeviceIdentity.fingerprintSha256(c));
    }

    @Test
    void storePasswordDerivedNotStored() {
        char[] a = DeviceIdentity.deriveStorePassword("s");
        char[] b = DeviceIdentity.deriveStorePassword("s");
        assertArrayEquals(new String(a).getBytes(), new String(b).getBytes());
        assertFalse(new String(a).contains("s"));
    }

    /** Self-signed di test (BC): solo struttura, firma reale. */
    static X509Certificate selfSigned(KeyPair kp, String dn) throws Exception {
        return selfSigned(kp, dn, 365);
    }

    static X509Certificate selfSigned(KeyPair kp, String dn, int days) throws Exception {
        long now = System.currentTimeMillis();
        org.bouncycastle.asn1.x500.X500Name name =
                new org.bouncycastle.asn1.x500.X500Name(dn);
        org.bouncycastle.cert.X509v3CertificateBuilder b =
                new org.bouncycastle.cert.X509v3CertificateBuilder(
                        name, java.math.BigInteger.valueOf(now),
                        new Date(now - 1000), new Date(now + days * 86400000L),
                        name,
                        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(
                                kp.getPublic().getEncoded()));
        org.bouncycastle.operator.ContentSigner signer =
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA")
                        .build(kp.getPrivate());
        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                .getCertificate(b.build(signer));
    }
}

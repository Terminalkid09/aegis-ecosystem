package com.aegis.guard.security;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TLS mutuo lato agent (gap-closing mTLS nativo).
 *
 * <p>Contesto TLS 1.3 con KeyManager (certificato device) + TrustManager
 * pinnato sulla CA server provisionata ({@code AEGIS_SERVER_CA}, es. CA
 * interna di Caddy distribuita via GPO/Intune). Senza CA provisionata
 * NON si costruisce alcun contesto permissivo: fail-closed (niente
 * trust-all, mai). Tutto stdlib JCA.
 */
public final class DeviceTls {

    private static final Logger log = LoggerFactory.getLogger(DeviceTls.class);

    private DeviceTls() {}

    /** CA server da file PEM, o null se assente/illeggibile (mai throw). */
    public static X509Certificate loadServerCa(Path pemFile) {
        if (pemFile == null || !Files.isRegularFile(pemFile)) return null;
        try (InputStream in = Files.newInputStream(pemFile)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(in);
        } catch (Exception e) {
            log.warn("CA server illeggibile ({}): niente TLS mutuo", e.getMessage());
            return null;
        }
    }

    /**
     * Contesto client TLS 1.3 con certificato device + CA pinnata.
     * Lancia se un pezzo manca: il chiamante degrada esplicitamente.
     */
    public static SSLContext buildClientContext(PrivateKey key, X509Certificate[] chain,
            X509Certificate serverCa) throws Exception {
        if (key == null || chain == null || chain.length == 0 || serverCa == null) {
            throw new IllegalArgumentException("chiave/catena/CA server obbligatori per mTLS");
        }
        KeyStore keys = KeyStore.getInstance("PKCS12");
        keys.load(null, null);
        keys.setKeyEntry("device", key, new char[0], chain);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keys, new char[0]);

        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        trust.setCertificateEntry("server-ca", serverCa);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);

        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }
}

package com.aegis.guard.security;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Handshake TLS mutui REALI in-JVM: server che richiede il cert client
 * (trust = CA di test) contro il contesto costruito da DeviceTls.
 */
class DeviceTlsTest {

    record TlsPeer(KeyPair key, X509Certificate cert) {}

    static class TestCa {
        final KeyPair key;
        final X509Certificate cert;

        TestCa() throws Exception {
            key = DeviceIdentity.generateKey();
            long now = System.currentTimeMillis();
            org.bouncycastle.asn1.x500.X500Name name =
                    new org.bouncycastle.asn1.x500.X500Name("CN=Test CA");
            org.bouncycastle.cert.X509v3CertificateBuilder b =
                    new org.bouncycastle.cert.X509v3CertificateBuilder(
                            name, java.math.BigInteger.valueOf(now),
                            new java.util.Date(now - 1000),
                            new java.util.Date(now + 86400000L),
                            name,
                            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(
                                    key.getPublic().getEncoded()));
            b.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints,
                    true, new org.bouncycastle.asn1.x509.BasicConstraints(true));
            org.bouncycastle.operator.ContentSigner signer =
                    new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                            "SHA256withECDSA").build(key.getPrivate());
            cert = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                    .getCertificate(b.build(signer));
        }

        TlsPeer issue(String cn) throws Exception {
            KeyPair k = DeviceIdentity.generateKey();
            long now = System.currentTimeMillis();
            org.bouncycastle.cert.X509v3CertificateBuilder b =
                    new org.bouncycastle.cert.X509v3CertificateBuilder(
                            new org.bouncycastle.asn1.x500.X500Name("CN=Test CA"),
                            java.math.BigInteger.valueOf(System.nanoTime()),
                            new java.util.Date(now - 1000),
                            new java.util.Date(now + 86400000L),
                            new org.bouncycastle.asn1.x500.X500Name("CN=" + cn),
                            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(
                                    k.getPublic().getEncoded()));
            org.bouncycastle.operator.ContentSigner signer =
                    new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                            "SHA256withECDSA").build(key.getPrivate());
            X509Certificate c = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                    .getCertificate(b.build(signer));
            return new TlsPeer(k, c);
        }
    }

    /** Server TLS che richiede cert client fidato alla CA data. */
    static int serveOnce(TestCa ca, BlockingQueue<String> result) throws Exception {
        TlsPeer server = ca.issue("server");
        java.security.KeyStore keys = java.security.KeyStore.getInstance("PKCS12");
        keys.load(null, null);
        keys.setKeyEntry("s", server.key().getPrivate(), new char[0],
                new X509Certificate[]{server.cert()});
        javax.net.ssl.KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance(
                javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keys, new char[0]);
        java.security.KeyStore trust = java.security.KeyStore.getInstance(
                java.security.KeyStore.getDefaultType());
        trust.load(null, null);
        trust.setCertificateEntry("ca", ca.cert);
        javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance(
                javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        SSLServerSocket ss = (SSLServerSocket) ctx.getServerSocketFactory()
                .createServerSocket();
        ss.setNeedClientAuth(true);
        ss.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        int port = ss.getLocalPort();
        Thread t = new Thread(() -> {
            try (SSLSocket s = (SSLSocket) ss.accept()) {
                s.startHandshake();
                java.security.cert.Certificate[] peer = s.getSession().getPeerCertificates();
                X509Certificate x = (X509Certificate) peer[0];
                result.offer("OK:" + x.getSubjectX500Principal().getName());
                // Drena la richiesta: chiudere con dati non letti causa RST
                // e il client perderebbe la risposta (flaky).
                try {
                    s.setSoTimeout(5000);
                    java.io.InputStream in = s.getInputStream();
                    StringBuilder req = new StringBuilder();
                    int b;
                    while ((b = in.read()) != -1) {
                        req.append((char) b);
                        if (req.length() > 4 && req.substring(req.length() - 4).equals("\r\n\r\n")) break;
                        if (req.length() > 4096) break;
                    }
                } catch (Exception ignored) {
                }
                // Risposta HTTP minima così il client verifica il canale.
                byte[] body = "ok".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                String head = "HTTP/1.0 200 OK\r\nContent-Length: " + body.length + "\r\n\r\n";
                s.getOutputStream().write(head.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                s.getOutputStream().write(body);
                s.getOutputStream().flush();
            } catch (Exception e) {
                result.offer("FAIL:" + e.getClass().getSimpleName());
            } finally {
                try {
                    ss.close();
                } catch (Exception ignored) {
                }
            }
        });
        t.setDaemon(true);
        t.start();
        return port;
    }

    static String clientHello(int port, SSLContext ctx) throws Exception {
        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket()) {
            s.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 5000);
            s.startHandshake();
            s.getOutputStream().write("GET / HTTP/1.0\r\n\r\n".getBytes());
            s.getOutputStream().flush();
            byte[] buf = new byte[128];
            int total = 0, n;
            s.setSoTimeout(5000);
            try {
                while (total < buf.length
                        && (n = s.getInputStream().read(buf, total, buf.length - total)) > 0) {
                    total += n;
                    if (total >= 15) break; // basta la status line
                }
            } catch (java.net.SocketTimeoutException e) {
                return total > 0 ? "HTTP-OK" : "EMPTY";
            }
            String head = new String(buf, 0, total, java.nio.charset.StandardCharsets.UTF_8);
            return head.startsWith("HTTP/1.0 200") ? "HTTP-OK" : "UNEXPECTED:" + head;
        }
    }

    @Test
    void mutualHandshakeSucceeds() throws Exception {
        TestCa ca = new TestCa();
        BlockingQueue<String> result = new ArrayBlockingQueue<>(1);
        int port = serveOnce(ca, result);
        TlsPeer device = ca.issue("agent-1");
        SSLContext client = DeviceTls.buildClientContext(
                device.key().getPrivate(),
                new X509Certificate[]{device.cert()}, ca.cert);
        assertEquals("HTTP-OK", clientHello(port, client));
        String seen = result.poll(10, TimeUnit.SECONDS);
        assertNotNull(seen);
        assertTrue(seen.startsWith("OK:"), seen);
        assertTrue(seen.contains("agent-1"), seen);
    }

    @Test
    void wrongCaRejected() throws Exception {
        TestCa ca = new TestCa();
        TestCa rogue = new TestCa();
        BlockingQueue<String> result = new ArrayBlockingQueue<>(1);
        int port = serveOnce(ca, result);
        TlsPeer evil = rogue.issue("agent-1");
        SSLContext client = DeviceTls.buildClientContext(
                evil.key().getPrivate(),
                new X509Certificate[]{evil.cert()}, rogue.cert);
        try {
            clientHello(port, client);
            fail("cert di CA sbagliata deve essere rifiutato");
        } catch (Exception e) {
            // SSLHandshakeException / EOF: rifiuto reale del server.
        }
        String seen = result.poll(10, TimeUnit.SECONDS);
        assertNotNull(seen);
        assertTrue(seen.startsWith("FAIL:"), seen);
    }

    @Test
    void missingPiecesFailClosed() throws Exception {
        TestCa ca = new TestCa();
        TlsPeer device = ca.issue("agent-1");
        assertThrows(IllegalArgumentException.class, () ->
                DeviceTls.buildClientContext(null,
                        new X509Certificate[]{device.cert()}, ca.cert));
        assertThrows(IllegalArgumentException.class, () ->
                DeviceTls.buildClientContext(device.key().getPrivate(), null, ca.cert));
        assertThrows(IllegalArgumentException.class, () ->
                DeviceTls.buildClientContext(device.key().getPrivate(),
                        new X509Certificate[]{device.cert()}, null));
        assertNull(DeviceTls.loadServerCa(Path.of("no-such-ca.pem")));
        assertNull(DeviceTls.loadServerCa(null));
    }

    @Test
    void serverCaLoadsFromPemFile() throws Exception {
        TestCa ca = new TestCa();
        Path f = Files.createTempFile("server-ca", ".pem");
        Files.writeString(f, DeviceIdentity.certToPem(ca.cert));
        X509Certificate loaded = DeviceTls.loadServerCa(f);
        assertNotNull(loaded);
        assertEquals(ca.cert, loaded);
    }
}

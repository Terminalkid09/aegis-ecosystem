package com.aegis.guard.hooks;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AuthenticodeVerifierTest {

    @Test
    void parseSubjectCn() {
        assertEquals("Microsoft Windows", AuthenticodeVerifier.parseSubjectCn(
                "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"));
        assertEquals("Foo", AuthenticodeVerifier.parseSubjectCn("cn=Foo, O=Bar"));
        assertEquals("Quoted, Name", AuthenticodeVerifier.parseSubjectCn("CN=\"Quoted, Name\", O=X"));
        assertEquals("", AuthenticodeVerifier.parseSubjectCn("O=NoCn Here"));
        assertEquals("", AuthenticodeVerifier.parseSubjectCn(null));
        assertEquals("", AuthenticodeVerifier.parseSubjectCn(""));
    }

    @Test
    void missingAndEmptyNeverThrow() {
        AuthenticodeVerifier.Result r = AuthenticodeVerifier.verify("C:\\definitely\\not\\here.exe");
        assertFalse(r.signed());
        assertFalse(r.error().isEmpty());
        assertFalse(AuthenticodeVerifier.verify(null).signed());
        assertFalse(AuthenticodeVerifier.verify("").signed());
        assertTrue(AuthenticodeVerifier.publisher(null).isEmpty());
    }

    @Test
    void unsignedTempFileIsNotTrusted() throws Exception {
        Path tmp = Files.createTempFile("aegis-unsigned", ".exe");
        Files.writeString(tmp, "MZ-not-really-signed");
        try {
            AuthenticodeVerifier.Result r = AuthenticodeVerifier.verify(tmp.toString());
            if (System.getProperty("os.name", "").toLowerCase().contains("win")) {
                assertFalse(r.signed(), "file spazzatura non deve risultare firmato");
                assertFalse(r.error().isEmpty());
            } else {
                assertEquals("not-windows", r.error());
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    @Test
    void systemBinaryIsTrustedOnWindows() {
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) return;
        String notepad = System.getenv("SystemRoot") + "\\System32\\notepad.exe";
        if (!Files.isRegularFile(Path.of(notepad))) return;
        AuthenticodeVerifier.Result r = AuthenticodeVerifier.verify(notepad);
        assertTrue(r.signed(), "notepad.exe di sistema deve essere firmato: " + r.error());
        assertEquals(0, r.errorCode());
    }

    @Test
    void publisherCacheBounded() {
        AuthenticodeVerifier.clearPublisherCache();
        AuthenticodeVerifier.publisher("C:\\definitely\\not\\here.exe");
        assertTrue(AuthenticodeVerifier.publisherCacheSize() <= 500);
        AuthenticodeVerifier.clearPublisherCache();
        assertEquals(0, AuthenticodeVerifier.publisherCacheSize());
    }
}

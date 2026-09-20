package com.aegis.guard.utils;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Interop crittografica: il vettore è firmato dal brain Python
 * (app/services/pki.py) — se questo test passa, le due implementazioni
 * concordano su canonico/Ed25519 e l'OTA non ha downgrade silenziosi.
 */
class ManifestVerifierTest {

    // Generato con pki.sign_manifest (brain). NON rigenerare a mano:
    // cambiarlo richiede rifirma dal brain.
    private static final String PUB =
            "l2EBppcwnLG+lH4IW/2QB0iC3mxiMHmpWP+ty2nGWCg=";
    private static final String MANIFEST =
            "{\"artifacts\":[{\"name\":\"aegis-guard-3.0.1.zip\","
            + "\"sha256\":\"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"}],"
            + "\"key_id\":\"aegis-manifest-v1\"}";
    private static final String SIG =
            "2c39d931ed3accac06e98b5d55a0d726d21eadc7727f0f79aa2a7fcb1d69fcaf96f4627"
            + "fef934b595bca1842733b4261d891beb18b3bb336d12e7a31bcb1d606";

    @Test
    void pythonSignedManifestVerifiesOnJvm() {
        assertTrue(ManifestVerifier.verifyEd25519(MANIFEST, SIG, PUB),
                "vettore firmato dal brain deve verificare sulla JVM");
    }

    @Test
    void tamperedManifestRejected() {
        String evil = MANIFEST.replace("3.0.1", "9.9.9-evil");
        assertFalse(ManifestVerifier.verifyEd25519(evil, SIG, PUB));
        assertFalse(ManifestVerifier.verifyEd25519(MANIFEST,
                "00".repeat(64), PUB));
    }

    @Test
    void badInputsFailClosed() {
        assertFalse(ManifestVerifier.verifyEd25519(null, SIG, PUB));
        assertFalse(ManifestVerifier.verifyEd25519(MANIFEST, null, PUB));
        assertFalse(ManifestVerifier.verifyEd25519(MANIFEST, SIG, null));
        assertFalse(ManifestVerifier.verifyEd25519(MANIFEST, SIG, ""));
        assertFalse(ManifestVerifier.verifyEd25519(MANIFEST, SIG, "AAAA"));
        assertFalse(ManifestVerifier.verifyEd25519(MANIFEST, "zz", PUB));
    }

    @Test
    void manifestCoversArtifactExactly() {
        assertTrue(ManifestVerifier.manifestCovers(MANIFEST,
                "aegis-guard-3.0.1.zip",
                "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"));
        assertFalse(ManifestVerifier.manifestCovers(MANIFEST,
                "aegis-guard-3.0.1.zip", "00".repeat(32)));
        assertFalse(ManifestVerifier.manifestCovers(MANIFEST,
                "evil.zip",
                "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
        assertFalse(ManifestVerifier.manifestCovers("not-json", "a", "b"));
    }
}

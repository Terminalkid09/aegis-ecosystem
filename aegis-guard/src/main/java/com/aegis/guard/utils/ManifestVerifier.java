package com.aegis.guard.utils;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Verifica manifest artefatti firmati Ed25519 (M6 Fase 7).
 *
 * <p>Il brain firma il manifest canonico (JSON, chiavi ordinate) con una
 * chiave Ed25519 dedicata (separata dalla CA); l'agente conosce solo la
 * pubblica via {@code AEGIS_MANIFEST_PUBKEY} (base64 raw 32B). Ed25519 è
 * nativo da JDK 15: nessuna dipendenza extra. Fallisce chiuso: qualunque
 * errore = firma invalida. La verifica HMAC esistente resta come compat.
 */
public final class ManifestVerifier {

    private ManifestVerifier() {}

    /** Prefisso SPKI DER per chiavi Ed25519 raw (RFC 8410). */
    private static final byte[] SPKI_PREFIX = {
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };

    /**
     * Verifica firma Ed25519 esadecimale su {@code manifestCanonicalJson}.
     *
     * @param pubKeyBase64 pubblica raw 32B in base64
     * @return true solo se la firma è valida
     */
    public static boolean verifyEd25519(String manifestCanonicalJson, String signatureHex,
            String pubKeyBase64) {
        if (manifestCanonicalJson == null || signatureHex == null || pubKeyBase64 == null
                || pubKeyBase64.isBlank()) {
            return false;
        }
        try {
            byte[] raw = Base64.getDecoder().decode(pubKeyBase64.trim());
            if (raw.length != 32) return false;
            byte[] spki = new byte[SPKI_PREFIX.length + 32];
            System.arraycopy(SPKI_PREFIX, 0, spki, 0, SPKI_PREFIX.length);
            System.arraycopy(raw, 0, spki, SPKI_PREFIX.length, 32);
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(spki));
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(pub);
            sig.update(manifestCanonicalJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return sig.verify(HexFormat.of().parseHex(signatureHex.trim()));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Controlla che l'artefatto atteso sia nel manifest firmato.
     * Confronto esatto nome+sha (case-insensitive sullo sha).
     */
    public static boolean manifestCovers(String manifestCanonicalJson, String name, String sha256) {
        if (manifestCanonicalJson == null || name == null || sha256 == null) return false;
        try {
            com.google.gson.JsonObject o =
                    com.google.gson.JsonParser.parseString(manifestCanonicalJson).getAsJsonObject();
            if (!o.has("artifacts") || !o.get("artifacts").isJsonArray()) return false;
            for (com.google.gson.JsonElement el : o.getAsJsonArray("artifacts")) {
                if (!el.isJsonObject()) continue;
                com.google.gson.JsonObject a = el.getAsJsonObject();
                if (!a.has("name") || !a.has("sha256")) continue;
                if (a.get("name").getAsString().equals(name)
                        && a.get("sha256").getAsString().equalsIgnoreCase(sha256.trim())) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }
}

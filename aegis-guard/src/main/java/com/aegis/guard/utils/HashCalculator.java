package com.aegis.guard.utils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
Calcola l'hash SHA-256 di un file su disco
usato per fingerprinting degli eseguibili rilevati
*/

public class HashCalculator {

    private static final Logger log = LoggerFactory.getLogger(HashCalculator.class);

    // Restituisce l'hash del file indicato dal path. In caso di errore restituisce la stringa vuota
    public String calculateHash(String filePath) {
        if (filePath == null || filePath.isBlank()) return "";
        Path path = Path.of(filePath);
        if(!Files.isReadable(path)) return "";

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream is = Files.newInputStream(path);
                DigestInputStream dis =new DigestInputStream(is, digest)) {
                    // Legge tutto il file in blocchi da 8kb
                    byte[] buf = new byte[8192];
                    while (dis.read(buf) != -1) {}
                }
                return bytesToHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new  IllegalStateException("SHA-256 not available", e);    
        } catch (IOException e) {
            log.debug("Impossible calculate hash of file for {}: {}", filePath, e.getMessage());
            return "";
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}


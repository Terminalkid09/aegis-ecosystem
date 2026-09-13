package com.aegis.guard.hooks;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.WString;
import com.sun.jna.win32.StdCallLibrary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Firma Authenticode via WinVerifyTrust (Fase 2, JNA, read-only).
 *
 * <p>{@link #verify(String)} dice se il file è firmato e fidato;
 * {@link #publisher(String)} estrae il CN del firmatario (via PowerShell,
 * con cache boundata — niente spawn ripetuti sotto storm di exec).
 * Non-Windows, file assenti o errori → non firmato/degradato, mai throw.
 */
public final class AuthenticodeVerifier {

    private static final Logger log = LoggerFactory.getLogger(AuthenticodeVerifier.class);

    private AuthenticodeVerifier() {}

    /** Binding minimo a wintrust.dll (solo verifica file). */
    public interface WinTrust extends StdCallLibrary {
        WinTrust INSTANCE = Native.load("wintrust", WinTrust.class);

        @Structure.FieldOrder({"Data1", "Data2", "Data3", "Data4"})
        class Guid extends Structure {
            public int Data1;
            public short Data2;
            public short Data3;
            public byte[] Data4 = new byte[8];

            Guid(int d1, short d2, short d3, byte[] d4) {
                Data1 = d1;
                Data2 = d2;
                Data3 = d3;
                System.arraycopy(d4, 0, Data4, 0, 8);
            }
        }

        @Structure.FieldOrder({"cbStruct", "pcwszFilePath", "hFile", "pgKnownSubject"})
        class FileInfo extends Structure {
            public int cbStruct;
            public WString pcwszFilePath;
            public Pointer hFile;
            public Pointer pgKnownSubject;

            public FileInfo() {
                cbStruct = size();
            }
        }

        @Structure.FieldOrder({"cbStruct", "pPolicyCallbackData", "pSIPClientData",
                "dwUIChoice", "fdwRevocationChecks", "dwUnionChoice", "pUnion",
                "dwStateAction", "hWVTStateData", "pwszURLReference",
                "dwProvFlags", "dwUIContext"})
        class TrustData extends Structure {
            public int cbStruct;
            public Pointer pPolicyCallbackData;
            public Pointer pSIPClientData;
            public int dwUIChoice;
            public int fdwRevocationChecks;
            public int dwUnionChoice;
            public Pointer pUnion;
            public int dwStateAction;
            public Pointer hWVTStateData;
            public Pointer pwszURLReference;
            public int dwProvFlags;
            public int dwUIContext;

            public TrustData() {
                cbStruct = size();
            }
        }

        int WinVerifyTrust(Pointer hwnd, Guid pgActionID, TrustData pWVTData);
    }

    private static final WinTrust.Guid VERIFY_V2 = new WinTrust.Guid(
            0x00AAC56B, (short) 0xCD44, (short) 0x11d0,
            new byte[]{(byte) 0x8C, (byte) 0xC2, 0x00, (byte) 0xC0,
                    0x4F, (byte) 0xC2, (byte) 0x95, (byte) 0xEE});

    private static final int WTD_UI_NONE = 2;
    // Audit: revoca catena INTERA (prima NONE: certificati rubati/revocati
    // risultavano trusted). WTD_REVOKE_WHOLECHAIN = 0x1.
    private static final int WTD_REVOKE_WHOLECHAIN = 1;
    private static final int WTD_CHOICE_FILE = 1;
    private static final int WTD_STATEACTION_IGNORE = 0;

    public record Result(boolean signed, long errorCode, String error, String source) {
        public Result(boolean signed, long errorCode, String error) {
            this(signed, errorCode, error, errorCode == 0 ? "wintrust" : "");
        }
    }

    /** Verifica firma+trust. Mai eccezioni. */
    public static Result verify(String path) {
        if (path == null || path.isBlank()) {
            return new Result(false, -1, "empty-path", "");
        }
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) {
            return new Result(false, -1, "not-windows", "");
        }
        java.io.File f = new java.io.File(path);
        if (!f.isFile()) {
            return new Result(false, -1, "not-found", "");
        }
        Result nativeResult = verifyNative(path);
        if (nativeResult.signed()) return nativeResult;
        // Fallback indipendente: cataloghi o ambienti dove wintrust è
        // parziale (es. NOSIGNATURE su file validi per PowerShell).
        // Accetta SOLO Status=Valid, mai UnknownError/NotSigned.
        String psStatus = authenticodeStatus(path);
        if ("Valid".equalsIgnoreCase(psStatus)) {
            return new Result(true, 0, "", "powershell");
        }
        return nativeResult;
    }

    static Result verifyNative(String path) {
        java.io.File f = new java.io.File(path);
        try {
            WinTrust.FileInfo info = new WinTrust.FileInfo();
            info.pcwszFilePath = new WString(f.getAbsolutePath());
            info.write();
            WinTrust.TrustData data = new WinTrust.TrustData();
            data.dwUIChoice = WTD_UI_NONE;
            data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
            data.dwUnionChoice = WTD_CHOICE_FILE;
            data.pUnion = info.getPointer();
            data.dwStateAction = WTD_STATEACTION_IGNORE;
            data.write();
            int rc = WinTrust.INSTANCE.WinVerifyTrust(Pointer.NULL, VERIFY_V2, data);
            long code = rc & 0xFFFFFFFFL;
            if (code == 0) return new Result(true, 0, "");
            return new Result(false, code, "HRESULT 0x" + Long.toHexString(code));
        } catch (UnsatisfiedLinkError | NoClassDefFoundError e) {
            return new Result(false, -1, "wintrust-unavailable");
        } catch (Exception e) {
            log.debug("WinVerifyTrust fallita per {}: {}", path, e.getMessage());
            return new Result(false, -1, "verify-error");
        }
    }

    private static final Map<String, String> PUBLISHER_CACHE = new ConcurrentHashMap<>();
    private static final int PUBLISHER_CACHE_MAX = 500;

    /** CN del firmatario (cache boundata) o vuoto. Mai eccezioni.
     * Audit: chiave = path+size+mtime (prima solo path: sostituendo il file
     * restava il publisher vecchio = trust avvelenato). */
    public static Optional<String> publisher(String path) {
        if (path == null || path.isBlank()) return Optional.empty();
        String cacheKey = cacheKey(path);
        String cached = PUBLISHER_CACHE.get(cacheKey);
        if (cached != null) return cached.isEmpty() ? Optional.empty() : Optional.of(cached);
        Optional<String> cn = queryPublisher(path);
        if (PUBLISHER_CACHE.size() >= PUBLISHER_CACHE_MAX) PUBLISHER_CACHE.clear();
        PUBLISHER_CACHE.put(cacheKey, cn.orElse(""));
        return cn;
    }

    static String cacheKey(String path) {
        try {
            java.nio.file.Path p = java.nio.file.Paths.get(path);
            java.nio.file.attribute.BasicFileAttributes a =
                    java.nio.file.Files.readAttributes(p, java.nio.file.attribute.BasicFileAttributes.class);
            return path + "|" + a.size() + "|" + a.lastModifiedTime().toMillis();
        } catch (Exception e) {
            return path;
        }
    }

    /** Status Get-AuthenticodeSignature (Valid/NotSigned/HashMismatch/...). Mai throw. */
    static String authenticodeStatus(String path) {
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) {
            return "";
        }
        try {
            String ps = "(Get-AuthenticodeSignature -LiteralPath '"
                    + path.replace("'", "''")
                    + "').Status";
            ProcessBuilder pb = new ProcessBuilder("powershell", "-NoProfile", "-NonInteractive",
                    "-Command", ps);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            return out.split("\\s+")[0];
        } catch (Exception e) {
            return "";
        }
    }

    static Optional<String> queryPublisher(String path) {
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) {
            return Optional.empty();
        }
        try {
            String ps = "(Get-AuthenticodeSignature -LiteralPath '"
                    + path.replace("'", "''")
                    + "').SignerCertificate.Subject";
            ProcessBuilder pb = new ProcessBuilder("powershell", "-NoProfile", "-NonInteractive",
                    "-Command", ps);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            String cn = parseSubjectCn(out);
            return cn.isEmpty() ? Optional.empty() : Optional.of(cn);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    /** Estrae CN=... da un Subject DN ("CN=Foo, O=Bar" → "Foo"). Puro.
     * Rispetta le virgolette (CN="Quoted, Name"). */
    public static String parseSubjectCn(String subject) {
        if (subject == null) return "";
        StringBuilder cur = new StringBuilder();
        boolean inQuotes = false;
        java.util.List<String> parts = new java.util.ArrayList<>();
        for (int i = 0; i < subject.length(); i++) {
            char c = subject.charAt(i);
            if (c == '"') {
                inQuotes = !inQuotes;
                cur.append(c);
            } else if (c == ',' && !inQuotes) {
                parts.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        parts.add(cur.toString());
        for (String part : parts) {
            String t = part.trim();
            if (t.regionMatches(true, 0, "CN=", 0, 3)) {
                String cn = t.substring(3).trim();
                if (cn.startsWith("\"") && cn.endsWith("\"") && cn.length() > 1) {
                    cn = cn.substring(1, cn.length() - 1);
                }
                return cn;
            }
        }
        return "";
    }

    static int publisherCacheSize() {
        return PUBLISHER_CACHE.size();
    }

    static void clearPublisherCache() {
        PUBLISHER_CACHE.clear();
    }
}

package com.aegis.guard.hooks;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Lettura read-only del Registry Windows via {@code reg.exe} (Fase 2).
 *
 * <p>Perché non {@code java.util.prefs.Preferences}: su Windows è radicato
 * in {@code HKLM\SOFTWARE\JavaSoft\Prefs} e NON può leggere chiavi reali
 * come {@code HKLM\SYSTEM\...} o le Run key — gli snapshot basati su
 * Preferences risultavano sempre vuoti su Windows veri (verificato).
 * {@code reg.exe} legge le stesse chiavi di PowerShell/ETW tooling.
 * Mai scritture, mai eccezioni: assenza binario/permessi → stringa vuota
 * e motivo degraded a carico del chiamante.
 */
public final class RegistryReader {

    private static final Logger log = LoggerFactory.getLogger(RegistryReader.class);

    private RegistryReader() {}

    /** Esegue `reg query <key>` (solo valori della chiave). Mai throw. */
    public static String queryKey(String key) {
        return runCapture(new String[]{"reg", "query", key}, 10);
    }

    /** Esegue `reg query <key> /s` (albero ricorsivo, es. Services). Mai throw. */
    public static String queryTree(String key) {
        return runCapture(new String[]{"reg", "query", key, "/s"}, 20);
    }

    static String runCapture(String[] command, int timeoutSeconds) {
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) {
            return "";
        }
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            boolean done = p.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!done) {
                p.destroyForcibly();
                return "";
            }
            return out;
        } catch (Exception e) {
            log.debug("reg query fallita: {}", e.getMessage());
            return "";
        }
    }

    private static final Pattern VALUE_LINE =
            Pattern.compile("^\\s+([^\\s].*?)\\s+(REG_\\w+)\\s+(.*)$");

    /**
     * Parso puro di `reg query` (singola chiave o /s): mappa
     * percorso-chiave-completo → {nome-valore → dati}. Le righe di
     * continuazione (MULTI_SZ) e gli header localizzati si ignorano.
     */
    public static Map<String, Map<String, String>> parseTree(String out) {
        Map<String, Map<String, String>> tree = new LinkedHashMap<>();
        if (out == null || out.isBlank()) return tree;
        String current = null;
        for (String raw : out.split("\\r?\\n")) {
            String line = raw.strip();
            if (line.isEmpty()) {
                current = null;
                continue;
            }
            if (line.regionMatches(true, 0, "HKEY_", 0, 5)) {
                current = line;
                tree.putIfAbsent(current, new LinkedHashMap<>());
                continue;
            }
            if (current == null) continue; // header localizzato ("..." etc.)
            Matcher m = VALUE_LINE.matcher(raw);
            if (m.matches()) {
                String name = m.group(1).trim();
                String data = m.group(3).trim();
                if (name.equalsIgnoreCase("(Default)") || name.equalsIgnoreCase("(Predefinito)")) {
                    name = "@default";
                }
                tree.get(current).put(name, data);
            }
        }
        return tree;
    }

    /** Valori della PRIMA chiave del dump (comodo per Run/Exclusions). */
    public static Map<String, String> parseValues(String out) {
        Map<String, Map<String, String>> tree = parseTree(out);
        if (tree.isEmpty()) return new LinkedHashMap<>();
        return tree.values().iterator().next();
    }

    /** Sottochiavi dirette presenti nel dump /s (basename). Puro. */
    public static List<String> subkeys(Map<String, Map<String, String>> tree, String parent) {
        List<String> out = new ArrayList<>();
        String prefix = parent.endsWith("\\") ? parent : parent + "\\";
        for (String key : tree.keySet()) {
            if (key.length() > prefix.length()
                    && key.regionMatches(true, 0, prefix, 0, prefix.length())) {
                String rest = key.substring(prefix.length());
                if (!rest.contains("\\")) out.add(rest);
            }
        }
        return out;
    }

    /** DWORD "0x3"/"3" → int, -1 se illeggibile. Puro. */
    public static int parseDword(String raw) {
        if (raw == null) return -1;
        String s = raw.trim().toLowerCase();
        try {
            if (s.startsWith("0x")) return (int) Long.parseLong(s.substring(2), 16);
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}

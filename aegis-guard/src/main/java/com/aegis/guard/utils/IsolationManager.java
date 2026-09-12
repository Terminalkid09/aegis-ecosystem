package com.aegis.guard.utils;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * Host isolation ("contain" alla CrowdStrike) — pure command builders + state.
 *
 * <p>Design onesto: siamo user-mode, quindi niente WFP callout driver né
 * eBPF. Usiamo il firewall OS (netsh / iptables) con allow-list del brain
 * così l'agente resta gestibile da SOC mentre il resto è tagliato fuori.
 * Lo stato è persistito su file per sopravvivere al reboot dell'agente.
 *
 * <p>Tutta la logica di costruzione comandi è pura e testata
 * ({@code IsolationManagerTest}) senza toccare il firewall in CI.
 */
public final class IsolationManager {

    private IsolationManager() {}

    public static final String STATE_FILE = "isolation.state";
    public static final String RULE_BLOCK_ALL = "Aegis_Isolate_Block_All";
    public static final String RULE_ALLOW_BRAIN = "Aegis_Isolate_Allow_Brain";

    /**
     * Estrae l'host da un URL brain (https://aegis.local:8443/api/v1 -&gt; aegis.local).
     * Ritorna "" se non parsabile — in quel caso si isola tutto (fail-closed).
     */
    public static String extractBrainHost(String brainUrl) {
        if (brainUrl == null || brainUrl.isBlank()) return "";
        try {
            URI uri = new URI(brainUrl.trim());
            String host = uri.getHost();
            if (host != null && !host.isBlank()) return host;
            // URL senza schema (es. "aegis.local:8000/api") — fallback manuale
            String s = brainUrl.trim().replaceFirst("^[a-zA-Z][a-zA-Z0-9+.-]*://", "");
            int cut = s.length();
            for (int i = 0; i < s.length(); i++) {
                char ch = s.charAt(i);
                if (ch == '/' || ch == ':' || ch == '?') { cut = i; break; }
            }
            return s.substring(0, cut);
        } catch (Exception e) {
            return "";
        }
    }

    public static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    /**
     * Comandi per isolare. Ogni elemento è un argv pronto per ProcessBuilder.
     * Se brainHost è vuoto: blocco totale senza eccezioni (fail-closed).
     */
    public static List<String[]> buildIsolateCommands(String brainHost) {
        List<String[]> cmds = new ArrayList<>();
        String brain = brainHost == null ? "" : brainHost.trim();
        if (isWindows()) {
            if (!brain.isEmpty()) {
                cmds.add(new String[]{"netsh", "advfirewall", "firewall", "add", "rule",
                        "name=" + RULE_ALLOW_BRAIN, "dir=out", "action=allow", "remoteip=" + brain});
            }
            cmds.add(new String[]{"netsh", "advfirewall", "firewall", "add", "rule",
                    "name=" + RULE_BLOCK_ALL, "dir=out", "action=block", "remoteip=any"});
        } else {
            cmds.add(new String[]{"iptables", "-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"});
            cmds.add(new String[]{"iptables", "-I", "OUTPUT", "1", "-m", "conntrack",
                    "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"});
            if (!brain.isEmpty()) {
                cmds.add(new String[]{"iptables", "-I", "OUTPUT", "1", "-d", brain, "-j", "ACCEPT"});
            }
            cmds.add(new String[]{"iptables", "-A", "OUTPUT", "-j", "DROP"});
        }
        return cmds;
    }

    /** Comandi per ripristinare la connettività (ordine inverso, best-effort). */
    public static List<String[]> buildRestoreCommands(String brainHost) {
        List<String[]> cmds = new ArrayList<>();
        String brain = brainHost == null ? "" : brainHost.trim();
        if (isWindows()) {
            cmds.add(new String[]{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + RULE_BLOCK_ALL});
            if (!brain.isEmpty()) {
                cmds.add(new String[]{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + RULE_ALLOW_BRAIN});
            }
        } else {
            cmds.add(new String[]{"iptables", "-D", "OUTPUT", "-j", "DROP"});
            if (!brain.isEmpty()) {
                cmds.add(new String[]{"iptables", "-D", "OUTPUT", "-d", brain, "-j", "ACCEPT"});
            }
            cmds.add(new String[]{"iptables", "-D", "OUTPUT", "-m", "conntrack",
                    "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"});
            cmds.add(new String[]{"iptables", "-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT"});
        }
        return cmds;
    }
}

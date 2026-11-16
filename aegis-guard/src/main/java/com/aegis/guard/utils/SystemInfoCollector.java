package com.aegis.guard.utils;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.concurrent.TimeUnit;

public class SystemInfoCollector {
    
    public static String getHostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return "unknown";
        }
    }

    /**
     * Identificatore stabile dell'host, inviato all'enrollment.
     *
     * Non è un segreto: il Brain ne conserva solo l'hash. Su piattaforme non
     * supportate ritorna stringa vuota, mai un valore inventato.
     */
    public static String getMachineId() {
        try {
            String os = System.getProperty("os.name", "").toLowerCase();
            if (os.contains("win")) {
                ProcessBuilder pb = new ProcessBuilder(
                        "reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
                        "/v", "MachineGuid");
                pb.redirectErrorStream(true);
                Process p = pb.start();
                String out = new String(p.getInputStream().readAllBytes());
                p.waitFor(5, TimeUnit.SECONDS);
                for (String line : out.split("\\r?\\n")) {
                    if (line.contains("MachineGuid")) {
                        String[] parts = line.trim().split("\\s+");
                        if (parts.length >= 3) return parts[parts.length - 1].trim();
                    }
                }
            } else if (os.contains("linux")) {
                for (String path : new String[]{"/etc/machine-id", "/var/lib/dbus/machine-id"}) {
                    try {
                        String value = Files.readString(Path.of(path)).trim();
                        if (!value.isEmpty()) return value;
                    } catch (IOException ignored) {
                        // Prova il percorso successivo.
                    }
                }
            } else if (os.contains("mac")) {
                ProcessBuilder pb = new ProcessBuilder(
                        "ioreg", "-rd1", "-c", "IOPlatformExpertDevice");
                pb.redirectErrorStream(true);
                Process p = pb.start();
                String out = new String(p.getInputStream().readAllBytes());
                p.waitFor(5, TimeUnit.SECONDS);
                int marker = out.indexOf("\"IOPlatformUUID\"");
                int eq = marker >= 0 ? out.indexOf('=', marker) : -1;
                int first = eq >= 0 ? out.indexOf('"', eq + 1) : -1;
                int last = first >= 0 ? out.indexOf('"', first + 1) : -1;
                if (last > first) return out.substring(first + 1, last).trim();
            }
        } catch (Exception ignored) {
            // Nessun identificatore: il Brain lo tratta come identità non legata.
        }
        return "";
    }

    public static String getIpAddress() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            String fallbackAddr = null;

            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (!iface.isUp() || iface.isLoopback()) continue;

                String ifaceName = iface.getName().toLowerCase();
                String displayName = iface.getDisplayName().toLowerCase();

                // Salta interfacce virtuali (Docker, WSL, Hyper-V, VMware)
                if (ifaceName.contains("vethernet") || ifaceName.contains("docker") ||
                    ifaceName.contains("vmnet") || ifaceName.contains("virtual") ||
                    displayName.contains("virtual") || displayName.contains("hyper-v") ||
                    displayName.contains("vmware") || displayName.contains("docker") ||
                    displayName.contains("wsl") || displayName.contains("bluetooth")) {
                    // Salva come fallback se nessuna interfaccia fisica trovata
                    if (fallbackAddr == null) {
                        var addresses = iface.getInetAddresses();
                        while (addresses.hasMoreElements()) {
                            var addr = addresses.nextElement();
                            if (!addr.isLoopbackAddress() && addr.getHostAddress().contains(".")) {
                                fallbackAddr = addr.getHostAddress();
                                break;
                            }
                        }
                    }
                    continue;
                }

                var addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    var addr = addresses.nextElement();
                    if (!addr.isLoopbackAddress() && addr.getHostAddress().contains(".")) {
                        return addr.getHostAddress();
                    }
                }
            }

            // Nessuna interfaccia fisica trovata, usa fallback (virtuale) o localhost
            if (fallbackAddr != null) return fallbackAddr;
            return InetAddress.getLocalHost().getHostAddress();
        } catch (Exception e) {
            return "N/A";
        }
    }
}

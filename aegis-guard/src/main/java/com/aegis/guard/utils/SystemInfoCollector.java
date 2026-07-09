package com.aegis.guard.utils;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;

public class SystemInfoCollector {
    
    public static String getHostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return "unknown";
        }
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

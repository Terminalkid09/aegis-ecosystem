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
            // Prova a ottenere l'IP locale dal container/host
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isUp() && !iface.isLoopback()) {
                    var addresses = iface.getInetAddresses();
                    while (addresses.hasMoreElements()) {
                        var addr = addresses.nextElement();
                        if (!addr.isLoopbackAddress() && addr.getHostAddress().contains(".")) {
                            return addr.getHostAddress();
                        }
                    }
                }
            }
            // Fallback: ritorna localhost
            return InetAddress.getLocalHost().getHostAddress();
        } catch (Exception e) {
            return "N/A";
        }
    }
}

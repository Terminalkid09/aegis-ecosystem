package com.aegis.guard.hooks;

import com.aegis.guard.network.AegisClient;
import com.aegis.guard.utils.HashCalculator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ProcessMonitorFactory {

    private static final Logger log = LoggerFactory.getLogger(ProcessMonitorFactory.class);

    private ProcessMonitorFactory() {} // utility class

    public static ProcessMonitor create(AegisClient client, HashCalculator hasher, String agentId) {
        String os = System.getProperty("os.name", "unknown").toLowerCase();
        log.info("Os detected: '{}'", os);

        if (os.contains("win")) {
            log.info("Selected WindowsProcessMonitor");
            return new WindowsProcessMonitor(client, hasher, agentId);
        }

        if (os.contains("nix") || os.contains("nux") || os.contains("linux")) {
            log.info("Selected LinuxProcessMonitor");
            return new LinuxProcessMonitor(client, hasher, agentId);
        }

        if (os.contains("mac") || os.contains("darwin")) {
            log.info("Selected MacOSProcessMonitor");
            return new MacOSProcessMonitor(client, hasher, agentId);
        }

        throw new UnsupportedOperationException(
            "Unsupported operating system: " + os +
            ". Operating system supported: Windows, Linux, MacOS."
        );
    }
}
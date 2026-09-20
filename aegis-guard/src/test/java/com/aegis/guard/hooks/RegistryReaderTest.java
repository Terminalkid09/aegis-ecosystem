package com.aegis.guard.hooks;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RegistryReaderTest {

    private static final String RUN_DUMP =
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\r\n"
        + "    OneDrive    REG_SZ    \"C:\\Program Files\\One.exe\" /background\r\n"
        + "    SecurityHealth    REG_EXPAND_SZ    %windir%\\system32\\SecurityHealthSystray.exe\r\n"
        + "\r\n";

    private static final String TREE_DUMP =
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\r\n"
        + "\r\n"
        + "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Dhcp\r\n"
        + "    DisplayName    REG_SZ    @%SystemRoot%\\system32\\dhcpcore.dll,-100\r\n"
        + "    ErrorControl    REG_DWORD    0x1\r\n"
        + "    ImagePath    REG_EXPAND_SZ    %SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p\r\n"
        + "    Start    REG_DWORD    0x2\r\n"
        + "\r\n"
        + "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NoStart\r\n"
        + "    DisplayName    REG_SZ    X\r\n"
        + "\r\n";

    @Test
    void parseValuesRunKey() {
        Map<String, String> vals = RegistryReader.parseValues(RUN_DUMP);
        assertEquals("\"C:\\Program Files\\One.exe\" /background", vals.get("OneDrive"));
        assertEquals("%windir%\\system32\\SecurityHealthSystray.exe", vals.get("SecurityHealth"));
        assertEquals(2, vals.size());
    }

    @Test
    void parseTreeServices() {
        Map<String, Map<String, String>> tree = RegistryReader.parseTree(TREE_DUMP);
        assertEquals(3, tree.size());
        Map<String, String> dhcp = tree.get(
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Dhcp");
        assertNotNull(dhcp);
        assertEquals("0x2", dhcp.get("Start"));
        assertTrue(dhcp.get("ImagePath").contains("svchost.exe"));
        List<String> subs = RegistryReader.subkeys(tree,
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services");
        assertTrue(subs.contains("Dhcp"));
        assertTrue(subs.contains("NoStart"));
        assertEquals(2, subs.size(), "solo figli diretti, niente nipoti");
    }

    @Test
    void parseTolerant() {
        assertTrue(RegistryReader.parseTree(null).isEmpty());
        assertTrue(RegistryReader.parseTree("").isEmpty());
        // Header localizzato + errore reg.exe: niente chiavi, niente throw.
        assertTrue(RegistryReader.parseTree(
                "ERRORE: impossibile trovare la chiave di registro specificata.\r\n").isEmpty());
        assertTrue(RegistryReader.parseValues("garbage\nmore garbage\n").isEmpty());
        // Default anonimo normalizzato.
        Map<String, String> vals = RegistryReader.parseValues(
                "HKEY_X\\Y\r\n    (Default)    REG_SZ    \r\n");
        assertTrue(vals.containsKey("@default"));
    }

    @Test
    void parseDword() {
        assertEquals(3, RegistryReader.parseDword("0x3"));
        assertEquals(2, RegistryReader.parseDword("2"));
        assertEquals(-1, RegistryReader.parseDword(null));
        assertEquals(-1, RegistryReader.parseDword(""));
        assertEquals(-1, RegistryReader.parseDword("abc"));
    }

    @Test
    void liveServicesReadableOnWindows() {
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) return;
        WindowsServiceSnapshot.Snapshot snap = WindowsServiceSnapshot.collect();
        assertEquals("", snap.degraded(), "reg.exe deve leggere i servizi: " + snap.degraded());
        assertFalse(snap.services().isEmpty(), "Windows reale ha servizi installati");
        // Dettagli on-demand sul primo servizio (niente dump /s completo).
        String first = snap.services().get(0).name();
        java.util.Map<String, java.util.Map<String, String>> det =
                WindowsServiceSnapshot.details(java.util.List.of(first), 5);
        assertNotNull(det);
        // Traversal e limiti rispettati.
        assertTrue(WindowsServiceSnapshot.details(
                java.util.List.of("..\\Windows Defender"), 5).isEmpty());
        assertTrue(WindowsServiceSnapshot.details(java.util.List.of(first), 0).isEmpty());
    }
}

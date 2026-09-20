package com.aegis.guard;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Audit L8: BLOCK_IP e DNS_SINKHOLE accettavano qualunque stringa e la
 * passavano a netsh/iptables o al file hosts. Questi test bloccano la
 * regressione: un valore non-IP non deve mai raggiungere il firewall e un
 * valore con newline non deve mai finire nel file hosts.
 */
class MainCommandValidationTest {

    // ─── isIpLiteral ────────────────────────────────────────────────────────

    @Test
    @DisplayName("IPv4 valido accettato")
    void acceptsValidIpv4() {
        assertTrue(Main.isIpLiteral("10.0.0.1"));
        assertTrue(Main.isIpLiteral("203.0.113.255"));
        assertTrue(Main.isIpLiteral("0.0.0.0"));
        assertTrue(Main.isIpLiteral(" 8.8.8.8 "));
    }

    @Test
    @DisplayName("IPv6 valido accettato")
    void acceptsValidIpv6() {
        assertTrue(Main.isIpLiteral("::1"));
        assertTrue(Main.isIpLiteral("2001:db8::1"));
        assertTrue(Main.isIpLiteral("fe80::1ff:fe23:4567:890a"));
    }

    @Test
    @DisplayName("Valori non-IP rifiutati (nessuna regola firewall arbitraria)")
    void rejectsNonIpValues() {
        assertFalse(Main.isIpLiteral("any"));
        assertFalse(Main.isIpLiteral("all"));
        assertFalse(Main.isIpLiteral(""));
        assertFalse(Main.isIpLiteral(null));
        assertFalse(Main.isIpLiteral("10.0.0"));
        assertFalse(Main.isIpLiteral("10.0.0.256"));
        assertFalse(Main.isIpLiteral("10.0.0.1/24"));
        assertFalse(Main.isIpLiteral("10.0.0.1 -j ACCEPT"));
        assertFalse(Main.isIpLiteral("10.0.0.1; rm -rf /"));
        assertFalse(Main.isIpLiteral("999.999.999.999"));
    }

    // ─── isDomainName ───────────────────────────────────────────────────────

    @Test
    @DisplayName("Dominio valido accettato")
    void acceptsValidDomains() {
        assertTrue(Main.isDomainName("evil.example.com"));
        assertTrue(Main.isDomainName("sub-domain.example.co.uk"));
        assertTrue(Main.isDomainName("EXAMPLE.com"));
    }

    @Test
    @DisplayName("Iniezione nel file hosts rifiutata")
    void rejectsHostsFileInjection() {
        assertFalse(Main.isDomainName(null));
        assertFalse(Main.isDomainName(""));
        assertFalse(Main.isDomainName("evil.com\n0.0.0.0 mybank.com"));
        assertFalse(Main.isDomainName("evil.com\r0.0.0.0 mybank.com"));
        assertFalse(Main.isDomainName("evil.com 0.0.0.0 mybank.com"));
        assertFalse(Main.isDomainName("evil.com#comment"));
        assertFalse(Main.isDomainName("single"));
        assertFalse(Main.isDomainName(".example.com"));
        assertFalse(Main.isDomainName("example..com"));
        assertFalse(Main.isDomainName("http://example.com"));
    }
}

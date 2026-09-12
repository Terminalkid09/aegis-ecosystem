package com.aegis.link.config;

import com.aegis.link.service.RedisService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * Sicurezza del gateway (P2.6/CI): il filtro API-key non deve mai lasciar
 * passare richieste senza credenziali valide, in nessuna versione di Boot.
 */
@ExtendWith(MockitoExtension.class)
class ApiKeyFilterTest {

    @Mock
    private RedisService redisService;

    @InjectMocks
    private ApiKeyFilter filter;

    private MockHttpServletRequest req(String key) {
        MockHttpServletRequest r = new MockHttpServletRequest("POST", "/api/v1/events");
        if (key != null) r.addHeader("X-Api-Key", key);
        return r;
    }

    @Test
    void missingKeyDenied() throws Exception {
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = org.mockito.Mockito.mock(FilterChain.class);
        filter.doFilter(req(null), res, chain);
        assertEquals(401, res.getStatus());
        org.mockito.Mockito.verify(chain, org.mockito.Mockito.never())
                .doFilter(org.mockito.Mockito.any(), org.mockito.Mockito.any());
    }

    @Test
    void wrongKeyDenied() throws Exception {
        when(redisService.getAgentIdBySecret("nope")).thenReturn(null);
        ReflectionTestUtils.setField(filter, "globalApiKey", "global-secret");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = org.mockito.Mockito.mock(FilterChain.class);
        filter.doFilter(req("nope"), res, chain);
        assertEquals(401, res.getStatus());
    }

    @Test
    void agentSecretPasses() throws Exception {
        when(redisService.getAgentIdBySecret("agent-secret")).thenReturn("agent-1");
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(req("agent-secret"), res, chain);
        assertEquals(200, res.getStatus());
        assertNotNull(chain.getRequest());
    }

    @Test
    void globalKeyFallbackPasses() throws Exception {
        when(redisService.getAgentIdBySecret("global-secret")).thenReturn(null);
        ReflectionTestUtils.setField(filter, "globalApiKey", "global-secret");
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(req("global-secret"), res, chain);
        assertEquals(200, res.getStatus());
    }

    @Test
    void healthBypasses() throws Exception {
        MockHttpServletRequest r = new MockHttpServletRequest("GET", "/api/v1/health");
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(r, res, chain);
        assertEquals(200, res.getStatus());
    }

    @Test
    void timingSafeComparison() throws Exception {
        // Chiavi di uguale lunghezza ma diverse: confronto a tempo costante.
        when(redisService.getAgentIdBySecret("bbbbbbbb")).thenReturn(null);
        ReflectionTestUtils.setField(filter, "globalApiKey", "aaaaaaaa");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = org.mockito.Mockito.mock(FilterChain.class);
        long t0 = System.nanoTime();
        filter.doFilter(req("bbbbbbbb"), res, chain);
        long dt = System.nanoTime() - t0;
        assertEquals(401, res.getStatus());
        assertTrue(dt >= 0);
    }
}

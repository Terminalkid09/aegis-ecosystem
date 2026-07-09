package com.aegis.link.config;

import com.aegis.link.service.RedisService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Collections;

@Component
public class ApiKeyFilter extends OncePerRequestFilter {

    @Value("${aegis.api.key}")
    private String globalApiKey;

    private final RedisService redisService;

    public ApiKeyFilter(RedisService redisService) {
        this.redisService = redisService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        // Escludi l'health check e l'enrollment (che è gestito da Brain) dalla validazione qui se necessario
        // Ma qui siamo in Link, che riceve solo eventi e comandi.
        if (path.startsWith("/actuator/") || path.equals("/api/v1/health")) {
            filterChain.doFilter(request, response);
            return;
        }

        String requestKey = request.getHeader("X-Api-Key");

        if (requestKey == null || requestKey.isBlank()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing X-Api-Key header");
            return;
        }

        // 1. Verifica se è un agente registrato tramite Redis
        String agentId = redisService.getAgentIdBySecret(requestKey);
        
        if (agentId != null) {
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    agentId, null, Collections.emptyList()
            );
            SecurityContextHolder.getContext().setAuthentication(auth);
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Fallback alla chiave globale (per test o management) - constant-time comparison
        if (globalApiKey != null && !globalApiKey.isBlank() && MessageDigest.isEqual(globalApiKey.getBytes(), requestKey.getBytes())) {
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    "aegis-admin", null, Collections.emptyList()
            );
            SecurityContextHolder.getContext().setAuthentication(auth);
            filterChain.doFilter(request, response);
        } else {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid X-Api-Key");
        }
    }
}

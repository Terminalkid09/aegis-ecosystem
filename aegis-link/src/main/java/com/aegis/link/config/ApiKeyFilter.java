package com.aegis.link.config;

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
import java.util.Collections;

/*
Filtro per la validazione della API Key.
Verifica che la richiesta contenga l'header X-Api-Key e che corrisponda
alla chiave configurata nel sistema. Se valida, setta l'Authentication
in Spring Security context in modo che il request passi le autorizzazioni.
*/
@Component
public class ApiKeyFilter extends OncePerRequestFilter {

    @Value("${aegis.api.key}")
    private String apiKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        
        // Escludi l'health check dalla validazione della API Key
        if (path.startsWith("/actuator/") || path.equals("/api/v1/health")) {
            filterChain.doFilter(request, response);
            return;
        }

        String requestKey = request.getHeader("X-Api-Key");

        if (apiKey == null || apiKey.isBlank()) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "API Key is not configured on server");
            return;
        }

        if (apiKey.equals(requestKey)) {
            // Set Spring Security authentication so the request passes authorization checks
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    "aegis-agent", null, Collections.emptyList()
            );
            SecurityContextHolder.getContext().setAuthentication(auth);
            filterChain.doFilter(request, response);
        } else {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or missing X-Api-Key header");
        }
    }
}

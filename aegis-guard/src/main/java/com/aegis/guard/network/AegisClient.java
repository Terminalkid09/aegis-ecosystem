package com.aegis.guard.network;

import com.aegis.guard.models.SystemEvent;
import com.aegis.guard.utils.Config;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializer;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/*
Client HTTP che invia gli eventi di sistema ad aegis-link.
Usa Apache HttpClient 5 con retry automatico e timeout configurati.
 */

public class AegisClient {

    private static final Logger log = LoggerFactory.getLogger(AegisClient.class);

    private static final int MAX_RETRIES    = 3;
    private static final int RETRY_DELAY_MS = 500;
    private static final String API_KEY = System.getenv("AEGIS_GUARD_API_KEY");

    private final Gson               gson;
    private final CloseableHttpClient httpClient;

    public AegisClient() {
        // Configurazione GSON per gestire il tipo Instant
        this.gson = new GsonBuilder()
                .registerTypeAdapter(Instant.class, (JsonSerializer<Instant>) (src, typeOfSrc, context) -> 
                        new JsonPrimitive(DateTimeFormatter.ISO_INSTANT.format(src)))
                .create();

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(Timeout.ofSeconds(5))
                .setResponseTimeout(Timeout.ofSeconds(10))
                .build();

        this.httpClient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build();
    }

    /*
    Serializza l'evento in JSON e lo invia ad aegis-link via POST.
    In caso di errore ritenta fino a MAX_RETRIES volte.
     */
    public void sendEvent(SystemEvent event) {
        String json = gson.toJson(event);
        log.debug("Sending event: {}", json);

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            try {
                HttpPost request = new HttpPost(Config.GATEWAY_URL);
                request.setEntity(new StringEntity(json, ContentType.APPLICATION_JSON));
                request.setHeader("X-Agent-Id", event.getAgentId());
                
                // Aggiungi la API Key se configurata
                if (API_KEY != null && !API_KEY.isBlank()) {
                    request.setHeader("X-Api-Key", API_KEY);
                }

                httpClient.execute(request, response -> {
                    int status = response.getCode();
                    if (status >= 200 && status < 300) {
                        log.debug("Event sent successfully (HTTP {})", status);
                    } else {
                        log.warn("aegis-link responded with HTTP {}", status);
                    }
                    return null;
                });
                return; // Successo: usciamo dal loop di retry

            } catch (IOException e) {
                log.warn("Attempt {}/{} failed: {}", attempt, MAX_RETRIES, e.getMessage());
                if (attempt < MAX_RETRIES) {
                    try { Thread.sleep(RETRY_DELAY_MS); } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                } else {
                    log.error("Impossible to send event after {} attempts. Event lost: {}",
                            MAX_RETRIES, event);
                }
            }
        }
    }

    public void close() {
        try { httpClient.close(); } catch (IOException e) {
            log.warn("Error closing HttpClient", e);
        }
    }

    /**
     * Recupera un comando pendente dal gateway (polling).
     */
    public String fetchCommand(String agentId) {
        String commandUrl = Config.GATEWAY_URL.replace("/events", "/commands");

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            try {
                HttpGet request = new HttpGet(commandUrl);
                request.setHeader("X-Agent-Id", agentId);
                if (API_KEY != null && !API_KEY.isBlank()) {
                    request.setHeader("X-Api-Key", API_KEY);
                }

                return httpClient.execute(request, response -> {
                    int status = response.getCode();
                    if (status == 200) {
                        return new String(response.getEntity().getContent().readAllBytes());
                    }
                    return null;
                });
            } catch (IOException e) {
                log.warn("Fetch command attempt {}/{} failed: {}", attempt, MAX_RETRIES, e.getMessage());
                if (attempt < MAX_RETRIES) {
                    try { Thread.sleep(RETRY_DELAY_MS); } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return null;
                    }
                }
            }
        }
        return null;
    }
}

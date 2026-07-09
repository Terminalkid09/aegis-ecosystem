package com.aegis.guard.network;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Map;

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

import com.aegis.guard.models.SystemEvent;
import com.aegis.guard.utils.Config;
import com.aegis.guard.utils.SystemInfoCollector;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializer;

public class AegisClient {

    private static final Logger log = LoggerFactory.getLogger(AegisClient.class);

    private static final int MAX_RETRIES    = 3;
    private static final int RETRY_DELAY_MS = 500;

    private final Gson                gson;
    private final CloseableHttpClient httpClient;
    private final String              reportUrl;
    private final String              commandUrl;
    private String agentSecret;

    public AegisClient() {
        this.reportUrl = Config.GATEWAY_URL;
        this.commandUrl = Config.BRAIN_URL + "/telemetry/commands";
        
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

    public void setAgentSecret(String secret) {
        this.agentSecret = secret;
    }

    public JsonObject enroll(String enrollKey) throws IOException {
        String enrollUrl = Config.BRAIN_URL + "/enroll/enroll";
        HttpPost request = new HttpPost(enrollUrl);
        
        JsonObject payload = new JsonObject();
        payload.addProperty("hostname", SystemInfoCollector.getHostname());
        payload.addProperty("os", System.getProperty("os.name"));
        payload.addProperty("enroll_key", enrollKey);
        
        request.setEntity(new StringEntity(gson.toJson(payload), ContentType.APPLICATION_JSON));
        
        return httpClient.execute(request, response -> {
            if (response.getCode() == 200) {
                byte[] content = response.getEntity().getContent().readAllBytes();
                return JsonParser.parseString(new String(content)).getAsJsonObject();
            } else {
                throw new IOException("Enrollment failed with status: " + response.getCode());
            }
        });
    }

    public void sendEvent(SystemEvent event) {
        if (event == null) return;
        String json = gson.toJson(event);

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            try {
                HttpPost request = new HttpPost(this.reportUrl);
                request.setEntity(new StringEntity(json, ContentType.APPLICATION_JSON));
                request.setHeader("X-Agent-Id", event.getAgentId());
                if (agentSecret != null) {
                    // Fix: Use standard Authorization header as expected by get_current_agent dependency
                    request.setHeader("Authorization", "Bearer " + agentSecret);
                }

                httpClient.execute(request, response -> {
                    int status = response.getCode();
                    if (status >= 200 && status < 300) {
                        log.debug("[OK] Event sent (HTTP {})", status);
                    } else {
                        log.warn("[WARN] Server responded with HTTP {}", status);
                    }
                    return null;
                });
                return;
            } catch (IOException e) {
                if (attempt == MAX_RETRIES) log.error("[ERROR] Failed to send event: {}", e.getMessage());
                try { Thread.sleep(RETRY_DELAY_MS * attempt); } catch (InterruptedException ie) { return; }
            }
        }
    }

    public String fetchCommand(String agentId) {
        try {
            HttpGet request = new HttpGet(this.commandUrl);
            request.setHeader("X-Agent-Id", agentId);
            if (agentSecret != null) {
                request.setHeader("Authorization", "Bearer " + agentSecret);
            }
            return httpClient.execute(request, response -> {
                if (response.getCode() == 200) {
                    byte[] content = response.getEntity().getContent().readAllBytes();
                    String body = new String(content).trim();
                    if (body.equals("null") || body.isEmpty()) {
                        return null;
                    }
                    return body;
                }
                return null;
            });
        } catch (IOException e) {
            log.warn("[WARN] Failed to fetch command: {}", e.getMessage());
            return null;
        }
    }

    public void close() {
        try { httpClient.close(); } catch (IOException e) { }
    }
}

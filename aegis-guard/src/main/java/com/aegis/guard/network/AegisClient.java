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
    private CloseableHttpClient httpClient;
    private final String              reportUrl;
    private final String              commandUrl;
    private String agentSecret;
    private String lastAgentId;

    // Identità device mTLS (gap-closing): chiave+cert locali, mai trasmessa la chiave.
    private volatile java.security.PrivateKey deviceKey;
    private volatile java.security.cert.X509Certificate[] deviceChain;
    private volatile long lastCertWarnMs;

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

    /**
     * Installa l'identità device: ricostruisce il client HTTP con contesto
     * TLS mutuo (cert device + CA server pinnata). Senza CA server resta il
     * TLS di default, ma l'header X-Client-Cert viaggia comunque (verifica
     * app-layer). Mai trust-all.
     */
    public synchronized void setIdentity(java.security.PrivateKey key,
            java.security.cert.X509Certificate[] chain,
            java.security.cert.X509Certificate serverCaOrNull) {
        this.deviceKey = key;
        this.deviceChain = chain;
        if (key != null && chain != null && chain.length > 0 && serverCaOrNull != null) {
            try {
                javax.net.ssl.SSLContext ctx =
                        com.aegis.guard.security.DeviceTls.buildClientContext(
                                key, chain, serverCaOrNull);
                org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory sf =
                        new org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory(ctx);
                org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager cm =
                        org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder
                                .create().setSSLSocketFactory(sf).build();
                RequestConfig requestConfig = RequestConfig.custom()
                        .setConnectionRequestTimeout(Timeout.ofSeconds(5))
                        .setResponseTimeout(Timeout.ofSeconds(10))
                        .build();
                CloseableHttpClient next = HttpClients.custom()
                        .setConnectionManager(cm)
                        .setDefaultRequestConfig(requestConfig)
                        .build();
                try {
                    this.httpClient.close();
                } catch (Exception ignored) {
                }
                this.httpClient = next;
                log.info("mTLS attivo: certificato device + CA server pinnata");
            } catch (Exception e) {
                log.warn("mTLS non attivabile ({}): solo header X-Client-Cert", e.getMessage());
            }
        }
    }

    /** Certificato device in base64(DER) single-line per l'header, o null. */
    public String deviceCertB64() {
        try {
            java.security.cert.X509Certificate[] chain = this.deviceChain;
            if (chain == null || chain.length == 0) return null;
            return java.util.Base64.getEncoder().encodeToString(chain[0].getEncoded());
        } catch (Exception e) {
            return null;
        }
    }

    /** Aggiunge l'header di mutua autenticazione quando l'identità esiste. */
    private void addIdentityHeader(org.apache.hc.core5.http.ClassicHttpRequest request) {
        String b64 = deviceCertB64();
        if (b64 != null) {
            request.setHeader("X-Client-Cert", b64);
        }
    }

    /** 401 con identità configurata: probabile revoca/scadenza → guida operatore (throttled). */
    private void warnCertProblem(int status) {
        if (status != 401 || deviceChain == null) return;
        long now = System.currentTimeMillis();
        if (now - lastCertWarnMs < 60000) return;
        lastCertWarnMs = now;
        log.warn("401 con certificato device: possibile REVOCA o scadenza — "
                + "ricontrollare enrollment sul SOC (nessun wipe automatico)");
    }

    public void setAgentSecret(String secret) {
        this.agentSecret = secret;
    }

    /** Accesso package-private: l'outbox deriva la chiave spool dal secret. */
    String getAgentSecret() {
        return this.agentSecret;
    }

    public void setAgentId(String agentId) {
        this.lastAgentId = agentId;
    }

    /**
     * Drena fino a N comandi in un round-trip. Ritorna lista vuota se niente.
     * null se il brain non ha il batch endpoint (vecchio) — il chiamante
     * cade sul singolo fetchCommand.
     */
    public java.util.List<String> fetchCommandsBatch(String agentId, int n) {
        try {
            HttpGet request = new HttpGet(this.commandUrl + "/batch?n=" + n);
            request.setHeader("X-Agent-Id", agentId);
            if (agentSecret != null) {
                request.setHeader("Authorization", "Bearer " + agentSecret);
            }
            addIdentityHeader(request);
            return httpClient.execute(request, response -> {
                if (response.getCode() == 404) return null;
                if (response.getCode() != 200) return new java.util.ArrayList<String>();
                byte[] content = response.getEntity().getContent().readAllBytes();
                String body = new String(content).trim();
                java.util.List<String> out = new java.util.ArrayList<>();
                try {
                    com.google.gson.JsonArray arr =
                            com.google.gson.JsonParser.parseString(body).getAsJsonArray();
                    for (com.google.gson.JsonElement el : arr) {
                        if (el.isJsonObject()) out.add(el.toString());
                        else if (el.isJsonPrimitive()) out.add(el.getAsString());
                    }
                } catch (Exception e) {
                    log.warn("[WARN] Bad batch body, falling back to single");
                    return null;
                }
                return out;
            });
        } catch (java.io.IOException e) {
            log.warn("[WARN] Failed to fetch command batch: {}", e.getMessage());
            return new java.util.ArrayList<String>();
        }
    }

    public JsonObject enroll(String enrollKey) throws IOException {        String enrollUrl = Config.BRAIN_URL + "/enroll/enroll";
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

    /**
     * Invia la CSR (chiave generata localmente) e ritorna il certificato PEM
     * firmato dalla Device CA. Usato solo in bootstrap/rinnovo controllato.
     */
    public String postCsr(String agentId, String csrPem) throws IOException {
        HttpPost request = new HttpPost(Config.BRAIN_URL + "/enroll/csr");
        JsonObject payload = new JsonObject();
        payload.addProperty("csr_pem", csrPem);
        request.setEntity(new StringEntity(gson.toJson(payload), ContentType.APPLICATION_JSON));
        request.setHeader("X-Agent-Id", agentId);
        if (agentSecret != null) {
            request.setHeader("Authorization", "Bearer " + agentSecret);
        }
        return httpClient.execute(request, response -> {
            int status = response.getCode();
            byte[] content = response.getEntity() == null ? new byte[0]
                    : response.getEntity().getContent().readAllBytes();
            if (status < 200 || status >= 300) {
                warnCertProblem(status);
                throw new IOException("CSR rejected with HTTP " + status + ": "
                        + new String(content));
            }
            JsonObject o = JsonParser.parseString(new String(content)).getAsJsonObject();
            if (!o.has("certificate_pem")) {
                throw new IOException("CSR response senza certificate_pem");
            }
            return o.get("certificate_pem").getAsString();
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
                addIdentityHeader(request);

                httpClient.execute(request, response -> {
                    int status = response.getCode();
                    if (status >= 200 && status < 300) {
                        log.debug("[OK] Event sent (HTTP {})", status);
                    } else {
                        log.warn("[WARN] Server responded with HTTP {}", status);
                        warnCertProblem(status);
                    }
                    return null;
                });
                return;
            } catch (IOException e) {
                if (attempt == MAX_RETRIES) log.error("[ERROR] Failed to send event: {}", e.getMessage());
                // Retry con jitter: senza, N agenti ripartono in sync dopo un
                // outage e picchiano il brain tutti insieme (thundering herd).
                long backoff = (long) RETRY_DELAY_MS * attempt
                        + java.util.concurrent.ThreadLocalRandom.current().nextInt(250);
                try { Thread.sleep(backoff); } catch (InterruptedException ie) { return; }
            }
        }
    }

    /**
     * Invia un batch a POST /telemetry/report/batch. Lancia
     * BatchUnsupportedException se il server non ha il batch endpoint
     * (brain vecchio → l'outbox cade in per-evento) o IOException per
     * errori transitori (→ spool persistente).
     */
    public void sendEventsBatch(java.util.List<SystemEvent> events) throws IOException {
        if (events == null || events.isEmpty()) return;
        String json = gson.toJson(events);
        String batchUrl = this.reportUrl.replace("/telemetry/report", "/telemetry/report/batch");
        HttpPost request = new HttpPost(batchUrl);
        request.setEntity(new StringEntity(json, ContentType.APPLICATION_JSON));
        request.setHeader("X-Agent-Id", events.get(0).getAgentId());
        if (agentSecret != null) {
            request.setHeader("Authorization", "Bearer " + agentSecret);
        }
        addIdentityHeader(request);
        httpClient.execute(request, response -> {
            int status = response.getCode();
            if (status == 404 || status == 405 || status == 501) {
                throw new BatchUnsupportedException("Batch not supported (HTTP " + status + ")");
            }
            if (status < 200 || status >= 300) {
                warnCertProblem(status);
                throw new IOException("Batch rejected with HTTP " + status);
            }
            log.debug("[OK] Batch of {} events sent", events.size());
            return null;
        });
    }

    /**
     * Acknowledge a queued command (ok/failed) so the SOC sees real execution
     * state instead of fire-and-forget. Best-effort: never throws — isolation
     * must work even if the ack itself fails.
     */
    public void ackCommand(String agentId, String command, String status, String details, Long alertId) {
        try {
            String ackUrl = Config.BRAIN_URL + "/telemetry/commands/ack";
            HttpPost request = new HttpPost(ackUrl);
            JsonObject payload = new JsonObject();
            payload.addProperty("command", command);
            payload.addProperty("status", status);
            if (details != null) payload.addProperty("details", details);
            if (alertId != null) payload.addProperty("alert_id", alertId);
            request.setEntity(new StringEntity(gson.toJson(payload), ContentType.APPLICATION_JSON));
            request.setHeader("X-Agent-Id", agentId);
            if (agentSecret != null) {
                request.setHeader("Authorization", "Bearer " + agentSecret);
            }
            addIdentityHeader(request);
            httpClient.execute(request, response -> null);
        } catch (Exception e) {
            log.warn("[WARN] Failed to ack command {}: {}", command, e.getMessage());
        }
    }

    /**
     * Scarica un artifact firmato in {@code dest} (usato da UPDATE_AGENT).
     * Autenticato come agente. Lo SHA/HMAC si verifica dopo, in UpdateManager.
     */
    public void downloadFile(String url, java.nio.file.Path dest) throws IOException {
        HttpGet request = new HttpGet(url);
        if (agentSecret != null) {
            request.setHeader("Authorization", "Bearer " + agentSecret);
        }
        // X-Agent-Id header is set by caller context via thread-local? No —
        // the brain's artifact endpoint requires it, so we pass the stored id
        // when available (set after enrollment).
        if (this.lastAgentId != null) {
            request.setHeader("X-Agent-Id", this.lastAgentId);
        }
        addIdentityHeader(request);
        httpClient.execute(request, response -> {
            int status = response.getCode();
            if (status < 200 || status >= 300) {
                throw new IOException("Artifact download failed with HTTP " + status);
            }
            try (var in = response.getEntity().getContent()) {
                java.nio.file.Files.copy(in, dest, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                throw new IOException("Artifact save failed: " + e.getMessage(), e);
            }
            return null;
        });
    }

    public String fetchCommand(String agentId) {
        // NOTE: fetchCommand reads X-Agent-Id from caller; the secret below
        // authenticates this agent (see get_current_agent on the brain).
        try {
            HttpGet request = new HttpGet(this.commandUrl);
            request.setHeader("X-Agent-Id", agentId);
            if (agentSecret != null) {
                request.setHeader("Authorization", "Bearer " + agentSecret);
            }
            addIdentityHeader(request);
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

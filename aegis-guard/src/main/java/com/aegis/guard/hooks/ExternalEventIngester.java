package com.aegis.guard.hooks;

import java.io.BufferedReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

import com.aegis.guard.models.SystemEvent;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Ingest di eventi kernel esterni (collector eBPF, consumer ETW) nella
 * pipeline Guard: ogni riga JSON {pid, ppid, comm, filename, event_type,
 * uid, ts_ns, ...v2} diventa un SystemEvent PROCESS_CREATED/PROCESS_EXITED/
 * CONNECTION_ESTABLISHED pronto per arricchimento (hash, parent name) e
 * invio al brain.
 *
 * <p>Contratto v2 ({@code event.schema.json}): i campi v2 sono tutti
 * opzionali — le righe legacy v1 restano valide. Parsing puro e testato
 * ({@code ExternalEventIngesterTest}) — il trasporto (pipe/file/stdout del
 * collector) resta fuori, qui solo mapping.
 */
public final class ExternalEventIngester {

    private ExternalEventIngester() {}

    /**
     * Converte una riga JSON del collector in SystemEvent.
     * Ritorna null se la riga non è un evento valido (mai eccezioni: il
     * flusso kernel non deve mai rompere il loop di ingest).
     */
    public static SystemEvent fromJsonLine(String agentId, String os, String agentVersion, String line) {
        if (agentId == null || line == null || line.isBlank()) return null;
        final JsonObject o;
        try {
            o = JsonParser.parseString(line).getAsJsonObject();
        } catch (Exception e) {
            return null;
        }
        if (!o.has("pid") || !o.has("event_type")) return null;
        try {
            long pid = o.get("pid").getAsLong();
            long ppid = o.has("ppid") ? o.get("ppid").getAsLong() : 0;
            String comm = o.has("comm") ? o.get("comm").getAsString() : "unknown";
            String filename = (o.has("filename") && !o.get("filename").isJsonNull())
                    ? o.get("filename").getAsString() : "";
            String type = o.get("event_type").getAsString();
            if (!("PROCESS_CREATED".equals(type) || "PROCESS_EXITED".equals(type)
                    || "CONNECTION_ESTABLISHED".equals(type))) return null;

            SystemEvent e = new SystemEvent(agentId, pid, ppid, "", comm, filename, "", os, type);
            e.setAgentVersion(agentVersion);
            // Campi v2 opzionali: presenti solo sulle righe nuove, mai richiesti.
            if (o.has("event_id") && !o.get("event_id").isJsonNull())
                e.setEventId(o.get("event_id").getAsString());
            if (o.has("schema_version")) {
                try { e.setSchemaVersion(o.get("schema_version").getAsInt()); } catch (Exception ignored) {}
            }
            if (o.has("boot_id") && !o.get("boot_id").isJsonNull())
                e.setBootId(o.get("boot_id").getAsString());
            if (o.has("seq")) {
                // Audit: seq senza boot_id e' orfana (il brain non puo'
                // ancorarla) e il contract la rifiuta: si scarta.
                if (e.getBootId() == null || e.getBootId().isBlank()) return null;
                try {
                    long seq = o.get("seq").getAsLong();
                    if (seq < 0) return null;
                    e.setSeq(seq);
                } catch (Exception ignored) {}
            }
            if (o.has("ts_ns")) {
                try {
                    long ts = o.get("ts_ns").getAsLong();
                    if (ts >= 0) e.setTsMonotonicNs(ts);
                } catch (Exception ignored) {}
            }
            if (o.has("ts_wall_ns")) {
                try {
                    long ts = o.get("ts_wall_ns").getAsLong();
                    if (ts >= 0) e.setTsWallNs(ts);
                } catch (Exception ignored) {}
            }
            if (o.has("proc_start_ns")) {
                try { e.setProcStartNs(o.get("proc_start_ns").getAsLong()); } catch (Exception ignored) {}
            }
            if (o.has("session") && !o.get("session").isJsonNull())
                e.setSessionId(o.get("session").getAsString());
            if (o.has("integrity") && !o.get("integrity").isJsonNull())
                e.setIntegrityLevel(o.get("integrity").getAsString());
            if (o.has("proto") && !o.get("proto").isJsonNull())
                e.setProto(o.get("proto").getAsString());
            if (o.has("direction") && !o.get("direction").isJsonNull())
                e.setDirection(o.get("direction").getAsString());
            if (o.has("container_id") && !o.get("container_id").isJsonNull())
                e.setContainerId(o.get("container_id").getAsString());
            if (o.has("cgroup") && !o.get("cgroup").isJsonNull())
                e.setCgroup(o.get("cgroup").getAsString());
            if (o.has("namespace") && !o.get("namespace").isJsonNull())
                e.setNetNamespace(o.get("namespace").getAsString());
            if (o.has("provenance") && !o.get("provenance").isJsonNull())
                e.setProvenance(o.get("provenance").getAsString());
            if (o.has("quality") && !o.get("quality").isJsonNull())
                e.setQuality(o.get("quality").getAsString());
            if ("CONNECTION_ESTABLISHED".equals(type) && o.has("remote") && !o.get("remote").isJsonNull()) {
                // Audit: JSON costruito con Gson (prima concatenazione con
                // solo rimozione delle virgolette: injection di voci extra).
                String remote = o.get("remote").getAsString();
                com.google.gson.JsonArray arr = new com.google.gson.JsonArray();
                com.google.gson.JsonObject conn = new com.google.gson.JsonObject();
                conn.addProperty("remote", remote);
                conn.addProperty("state", "ESTABLISHED");
                arr.add(conn);
                e.setNetworkConnections(arr.toString());
            }
            return e;
        } catch (Exception e) {
            return null;
        }
    }

    /** Variante produzione: versione da Config. */
    public static SystemEvent fromJsonLine(String agentId, String os, String line) {
        return fromJsonLine(agentId, os, com.aegis.guard.utils.Config.AGENT_VERSION, line);
    }

    /** Legge un flusso di righe JSON e ritorna gli eventi validi. */
    public static List<SystemEvent> readAll(String agentId, String os, String agentVersion, Reader in) {
        List<SystemEvent> out = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(in)) {
            String line;
            while ((line = br.readLine()) != null) {
                SystemEvent e = fromJsonLine(agentId, os, agentVersion, line);
                if (e != null) out.add(e);
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    /** Variante produzione: versione da Config. */
    public static List<SystemEvent> readAll(String agentId, String os, Reader in) {
        return readAll(agentId, os, com.aegis.guard.utils.Config.AGENT_VERSION, in);
    }
}

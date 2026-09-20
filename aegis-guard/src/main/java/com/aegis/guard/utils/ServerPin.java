package com.aegis.guard.utils;

/**
 * Pin del server (M6 Fase 7): l'agente ricorda il BRAIN_URL del primo
 * enrollment e rifiuta di parlare con un server diverso senza re-enroll.
 *
 * <p>Chi cambia il server di un agente ne dirotta telemetria e comandi
 * (incluso UPDATE_AGENT): il cambio silenzioso via env/config è vietato,
 * fail-closed con messaggio che spiega il re-enroll. Puro e testabile.
 */
public final class ServerPin {

    private ServerPin() {}

    /**
     * @param storedUrl  URL salvato all'enrollment (può mancare sui vecchi secret)
     * @param currentUrl URL effettivo da Config
     * @return null se ok, altrimenti messaggio d'errore fatale
     */
    public static String check(String storedUrl, String currentUrl) {
        String current = currentUrl == null ? "" : currentUrl.trim();
        if (current.isEmpty()) return "BRAIN_URL non configurato — refusing";
        if (storedUrl == null || storedUrl.isBlank()) return null; // legacy: pin da ora
        String stored = storedUrl.trim().replaceAll("/+$", "");
        String cur = current.replaceAll("/+$", "");
        if (stored.equalsIgnoreCase(cur)) return null;
        return "Server cambiato (stored=" + stored + " current=" + cur
                + "): re-enroll richiesto, rifiuto connessioni";
    }

    public static String normalize(String url) {
        if (url == null) return "";
        return url.trim().replaceAll("/+$", "");
    }
}

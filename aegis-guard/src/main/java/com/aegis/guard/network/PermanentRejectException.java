package com.aegis.guard.network;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Il server ha respinto il payload per quello che CONTIENE (schema non valido,
 * troppo grande, tipo non supportato): ritentare lo stesso byte identico non
 * potrà mai riuscire.
 *
 * <p>Perché serve una classe a parte: prima un 422 era un {@link IOException}
 * come un timeout, quindi l'outbox lo rimetteva in spool. Ma lo spool viene
 * rigiocato a ogni flush partendo dalle righe vecchie: un evento che il server
 * rifiuta per sempre restava in testa alla coda e bloccava <em>tutto</em> il
 * resto, per sempre. Sintomo osservato: `/telemetry/report/batch` rispondeva
 * 422 a ogni flush, lo spool cresceva e la telemetria del sensore non arrivava
 * mai al brain.
 *
 * <p>Quando il corpo del 422 è leggibile si estrae l'indice degli elementi
 * colpevoli (FastAPI mette {@code loc: ["body", <indice>, <campo>]}), così si
 * scartano SOLO quelli e si conservano i sani.
 */
public class PermanentRejectException extends IOException {

    private static final Pattern LOC_INDEX =
            Pattern.compile("\"loc\"\\s*:\\s*\\[\\s*\"body\"\\s*,\\s*(\\d+)");

    private final List<Integer> offendingIndexes;

    public PermanentRejectException(String message, String responseBody) {
        super(message);
        this.offendingIndexes = parseIndexes(responseBody);
    }

    /** Indici (0-based) degli elementi respinti, vuoto se non deducibili. */
    public List<Integer> getOffendingIndexes() {
        return offendingIndexes;
    }

    static List<Integer> parseIndexes(String body) {
        if (body == null || body.isEmpty()) return Collections.emptyList();
        Matcher m = LOC_INDEX.matcher(body);
        List<Integer> out = new ArrayList<>();
        while (m.find()) {
            try {
                int idx = Integer.parseInt(m.group(1));
                if (!out.contains(idx)) out.add(idx);
            } catch (NumberFormatException ignored) {
                // corpo parziale: si degrada al caso "indici non noti"
            }
        }
        Collections.sort(out);
        return out;
    }
}

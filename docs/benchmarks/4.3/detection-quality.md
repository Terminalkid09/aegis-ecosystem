# Detection quality baseline — Aegis 4.3

Generato: `2026-11-19T10:06:12.455552+00:00`

> Baseline sintetica e riproducibile. **Non** e' un tasso di FP/FN di
> produzione: gli eventi sono costruiti e nessun malware viene eseguito.
> Il confronto 5.0 deve usare lo stesso set e lo stesso comando.

## Metriche

| Metrica | Valore |
|---|---:|
| Casi malicious | 14 |
| Casi benigni | 14 |
| True positive | 14 |
| False negative | 0 |
| False positive | 5 |
| True negative | 9 |
| Precision | 0.737 |
| Recall | 1.000 |
| F1 | 0.848 |
| False positive rate | 0.357 |

## Casi

| ID | Gruppo | Atteso | Rilevato | Severita | Regole |
|---|---|---|---|---|---|
| `mal-office-powershell` | malicious | sì | sì | CRITICAL | AEGIS-S002, AEGIS-S007, AEGIS-S009, AEGIS-S012 |
| `mal-encoded-only` | malicious | sì | sì | HIGH | AEGIS-S007, AEGIS-S009, AEGIS-S012 |
| `mal-certutil-download` | malicious | sì | sì | HIGH | AEGIS-S012 |
| `mal-renamed-mimikatz` | malicious | sì | sì | CRITICAL | AEGIS-S001, AEGIS-S004, AEGIS-S015 |
| `mal-chrome-svchost` | malicious | sì | sì | HIGH | AEGIS-S002 |
| `mal-thread-201` | malicious | sì | sì | MEDIUM | AEGIS-S013 |
| `mal-thread-300` | malicious | sì | sì | MEDIUM | AEGIS-S013 |
| `mal-dll-side-load` | malicious | sì | sì | HIGH | AEGIS-S011 |
| `mal-run-key` | malicious | sì | sì | HIGH | AEGIS-S016 |
| `mal-schtasks-encoded` | malicious | sì | sì | CRITICAL | AEGIS-S012, AEGIS-S017 |
| `mal-system-powershell` | malicious | sì | sì | CRITICAL | AEGIS-S002, AEGIS-S009 |
| `mal-double-extension` | malicious | sì | sì | HIGH | AEGIS-S004, AEGIS-S006 |
| `hard-rundll32-javascript` | malicious | sì | sì | MEDIUM | AEGIS-S002, AEGIS-S009 |
| `hard-mshta-url` | malicious | sì | sì | HIGH | AEGIS-S009, AEGIS-S012 |
| `benign-chrome` | benign | no | no | NONE | — |
| `benign-powershell-getchilditem` | benign | no | sì | MEDIUM | AEGIS-S002, AEGIS-S009 |
| `benign-cmd-dir` | benign | no | sì | MEDIUM | AEGIS-S002, AEGIS-S009 |
| `benign-python-print` | benign | no | sì | MEDIUM | AEGIS-S009 |
| `benign-certutil-hash` | benign | no | no | NONE | — |
| `benign-rundll32-printui` | benign | no | sì | MEDIUM | AEGIS-S009 |
| `benign-svchost-empty-path` | benign | no | no | NONE | — |
| `benign-explorer-chrome` | benign | no | no | NONE | — |
| `benign-whoami` | benign | no | no | NONE | — |
| `benign-reg-query` | benign | no | no | NONE | — |
| `benign-schtasks-query` | benign | no | no | NONE | — |
| `benign-edge-renderer` | benign | no | no | NONE | — |
| `benign-notepad-temp` | benign | no | no | NONE | — |
| `benign-signed-installer` | benign | no | sì | LOW | AEGIS-S004 |

## Soglia thread

| Thread | Rilevato | Severita |
|---:|---|---|
| 180 | no | NONE |
| 200 | no | NONE |
| 201 | sì | MEDIUM |
| 300 | sì | MEDIUM |

## Lettura onesta

- I falsi positivi benigni sono quasi tutti interpreti (`powershell`, `cmd`,
  `python`) e installer firmati in Downloads: sono alert a bassa/media
  severita', non incidenti automatici.
- I casi `hard-*` misurano tecniche che le regole attuali possono perdere;
  sono la parte da migliorare nella 5.0, non una promessa di copertura.
- La soglia thread e' un test della regola, non del sensore: il campo
  `thread_count` e' popolato dal collector, ma qui viene simulato.

## Uso per il confronto 5.0

- Il set va congelato: non aggiungere o togliere casi dal file 4.3, o il
  confronto perde senso. Eventuali casi nuovi vanno in un set separato.
- In questo panel: **14 TP, 0 FN, 5 FP, 9 TN**. I 5 FP sono
  tre interpreti (`powershell`, `cmd`, `python`), `rundll32 printui` e un
  installer firmato in Downloads: sono alert bassi/medi, non incidenti.
- `recall=1.000` non e' una promessa: dice che questo panel non contiene
  una tecnica che le regole attuali perdono. Il tasso reale va misurato su
  host e traffico reali.
- La 5.0 deve riusare lo stesso comando e lo stesso set, e dichiarare se
  il motore o le regole sono cambiati.

## Prossimo passo — AP-127

- Questo file e' la baseline congelata per il confronto 4.3 → 5.0.
- AP-127 (post-4.3) aggiunge un corpus benigno di strumenti
  amministrativi con argomenti insoliti, misurando FP/FN per host/giorno
  e senza nascondere regressioni. Non e' una promessa di produzione.

Ripetere con:

```bash
PYTHONPATH=aegis-brain .venv315/Scripts/python.exe scripts/detection_quality.py
```

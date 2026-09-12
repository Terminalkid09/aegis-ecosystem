"""Replay report riproducibile (Fase 6): metriche detection su corpus versionato.

Uso:
    python scripts/replay_report.py [--seed 42]
        or
    python scripts/replay_report.py [--json]   # output JSON completo

Riproduce precision/recall/F1 e FP-per-host-day sugli stessi dati sorgente;
MTTD non è misurabile qui (serve telemetria live) e viene dichiarato tale.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "aegis-brain"))

from app.services.replay import score_corpus, DATASET_VERSION, CORPUS_HOST_DAYS  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay detection report (deterministic)")
    parser.add_argument("--seed", type=int, default=None, help="seed riproducibile per sharding")
    parser.add_argument("--json", action="store_true", help="output JSON completo")
    args = parser.parse_args()

    rep = score_corpus(seed=args.seed)

    if args.json:
        print(json.dumps(rep, indent=2, default=str))
        return 0

    print(f"Aegis static detection — replay report")
    print(f"  dataset_version : {rep['dataset_version']}")
    print(f"  seed           : {rep['seed']}")
    print(f"  rules          : {rep['rules']}")
    print(f"  corpus         : benign {rep['benign_lines']} | suspicious {rep['suspicious_lines']} | malformed {rep['malformed_lines']} (invalid {rep['malformed_invalid']})")
    print(f"  TP / FP / FN   : {rep['tp']} / {rep['fp']} / {rep['fn']}")
    print(f"  precision      : {rep['precision']}")
    print(f"  recall         : {rep['recall']}")
    print(f"  F1             : {rep['f1']}")
    print(f"  FP/host-day    : {rep['false_positives_per_host_day']}  (assunzione {rep['host_days_assumption']} host-day)")
    print(f"  MTTD           : {rep['mttd_seconds']}  ({rep['mttd_note']})")
    if rep["fn_line_indexes"]:
        print(f"  FN lines (index): {rep['fn_line_indexes']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
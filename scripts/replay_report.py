"""Replay report riproducibile (Fase 6): metriche detection su corpus versionato.

Uso:
    python scripts/replay_report.py [--seed 42]
    python scripts/replay_report.py [--split <training|validation|regression>]
    python scripts/replay_report.py --all
        or
    python scripts/replay_report.py [--json]   # output JSON completo

Riproduce precision/recall/F1 e FP-per-host-day sugli stessi dati sorgente;
MTTD non è misurabile qui (serve telemetria live) e viene dichiarato tale.
Ogni split (training/validation/regression) è un corpus indipendente.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "aegis-brain"))

from app.services.replay import (  # noqa: E402
    score_corpus, score_all_splits, DATASET_VERSION, DATASET_SPLITS, CORPUS_HOST_DAYS,
)


def _print_human(rep: dict) -> None:
    print(f"  dataset_version : {rep['dataset_version']}")
    print(f"  split          : {rep['split']}")
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay detection report (deterministic)")
    parser.add_argument("--seed", type=int, default=None, help="seed riproducibile per sharding")
    parser.add_argument("--split", choices=list(DATASET_SPLITS), default="training",
                        help="split corpus indipendente da scrorare")
    parser.add_argument("--all", action="store_true", help="scorra tutti gli split indipendenti")
    parser.add_argument("--json", action="store_true", help="output JSON completo")
    args = parser.parse_args()

    if args.all:
        splits = score_all_splits(seed=args.seed)
        if args.json:
            print(json.dumps(splits, indent=2, default=str))
            return 0
        print("Aegis static detection — replay report (tutti gli split indipendenti)")
        for split in DATASET_SPLITS:
            print(f"[{split}]")
            _print_human(splits[split])
            print()
        return 0

    rep = score_corpus(seed=args.seed, split=args.split)

    if args.json:
        print(json.dumps(rep, indent=2, default=str))
        return 0

    print("Aegis static detection — replay report")
    _print_human(rep)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
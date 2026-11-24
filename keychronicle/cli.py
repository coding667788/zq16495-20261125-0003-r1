from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from .crypto import new_sample_key_hex
from .diff import diff_bundle_snapshots, diff_knowledge_cuts
from .engine import AuditEngine
from .errors import KeychronicleError
from .loader import load_bundle


def _utf8_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")


def _write_json(payload: Any, output: str | None, *, compact: bool = False) -> None:
    text = json.dumps(
        payload,
        ensure_ascii=False,
        indent=None if compact else 2,
        separators=(",", ":") if compact else None,
        sort_keys=False,
    )
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    else:
        sys.stdout.write(text + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keychronicle",
        description="Offline HMAC trust audit with temporal knowledge cuts.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="audit every approval in BUNDLE")
    audit.add_argument("bundle_pos", nargs="?", metavar="BUNDLE", help="bundle.json or directory")
    audit.add_argument("--bundle", dest="bundle_opt", help="alternative BUNDLE argument")
    audit.add_argument("--issued-at", "--at", dest="issued_at", help="ISO-8601 issuance instant T")
    audit.add_argument("--known-at", "--knowledge-at", dest="known_at", help="ISO-8601 knowledge cutoff K")
    audit.add_argument("--threshold", type=int, default=None)
    audit.add_argument("--output", "-o", default=None)
    audit.add_argument("--compact", action="store_true", help="emit compact JSON")
    audit.add_argument(
        "--edges",
        dest="with_edges",
        action="store_true",
        help="include every signature/reference/validity edge status",
    )
    audit.add_argument(
        "--no-signature-reports",
        action="store_true",
        help="omit per-signature cryptographic diagnostics",
    )

    diff = sub.add_parser("diff", help="compare two knowledge cutoffs for one bundle")
    diff.add_argument("bundle_pos", nargs="?", metavar="BUNDLE", help="bundle.json or directory")
    diff.add_argument(
        "cuts",
        nargs="*",
        metavar="K",
        help="optional two positional knowledge cuts: K1 K2",
    )
    diff.add_argument("--bundle", dest="bundle_opt", help="alternative BUNDLE argument")
    diff.add_argument("--early-bundle", dest="early_bundle", help="optional first snapshot")
    diff.add_argument("--late-bundle", dest="late_bundle", help="optional second snapshot")
    diff.add_argument("--issued-at", "--at", dest="issued_at", help="ISO-8601 issuance instant T")
    diff.add_argument(
        "--from-known-at",
        "--before-known-at",
        "--earlier-known-at",
        dest="from_known_at",
    )
    diff.add_argument(
        "--to-known-at",
        "--after-known-at",
        "--later-known-at",
        dest="to_known_at",
    )
    diff.add_argument("--threshold", type=int, default=None)
    diff.add_argument("--output", "-o", default=None)
    diff.add_argument("--compact", action="store_true")

    keygen = sub.add_parser("keygen", help="synthesize an offline sample HMAC key")
    keygen.add_argument("--issuer-id", default="sample-issuer")
    keygen.add_argument("--key-id", default="sample-key-1")
    keygen.add_argument("--bytes", type=int, default=32)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    _utf8_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "keygen":
            payload = {
                "key_id": args.key_id,
                "issuer_id": args.issuer_id,
                "algorithm": "HMAC-SHA256",
                "secret_hex": new_sample_key_hex(args.bytes),
            }
            _write_json(payload, None, compact=False)
            return 0

        bundle_path = getattr(args, "bundle_opt", None) or getattr(args, "bundle_pos", None)
        if not bundle_path:
            raise KeychronicleError("a BUNDLE path is required")
        bundle = load_bundle(bundle_path)
        issued_at = args.issued_at or bundle.get("issued_at")
        known_at = getattr(args, "known_at", None) or bundle.get("known_at")

        if args.command == "audit":
            if not issued_at or not known_at:
                raise KeychronicleError("audit requires --issued-at T and --known-at K")
            engine = AuditEngine(
                bundle,
                issued_at,
                known_at,
                threshold=args.threshold,
            )
            report = engine.audit(build_edges=args.with_edges)
            if args.with_edges:
                report["edges"] = sorted(
                    engine.edge_results.values(), key=lambda edge: edge["edge_id"]
                )
            if args.no_signature_reports:
                report.pop("signature_reports", None)
                report.pop("checkpoint_reports", None)
            _write_json(report, args.output, compact=args.compact)
            return 0

        if args.command == "diff":
            positional_cuts = list(getattr(args, "cuts", []) or [])
            late_snapshot_path = getattr(args, "late_bundle", None)
            if (
                not late_snapshot_path
                and len(positional_cuts) == 1
                and Path(positional_cuts[0]).exists()
            ):
                late_snapshot_path = positional_cuts[0]

            if getattr(args, "early_bundle", None) or late_snapshot_path:
                early_path = getattr(args, "early_bundle", None) or bundle_path
                late_path = late_snapshot_path or bundle_path
                early_bundle = load_bundle(early_path)
                late_bundle = load_bundle(late_path)
                snapshot_issued_at = issued_at or late_bundle.get("issued_at")
                if not snapshot_issued_at:
                    raise KeychronicleError("snapshot diff requires --issued-at T")
                report = diff_bundle_snapshots(
                    early_bundle,
                    late_bundle,
                    snapshot_issued_at,
                    from_known_at=args.from_known_at,
                    to_known_at=args.to_known_at,
                    threshold=args.threshold,
                )
                _write_json(report, args.output, compact=args.compact)
                return 0

            from_known_at = (
                args.from_known_at
                or (positional_cuts[0] if len(positional_cuts) >= 1 else None)
                or bundle.get("from_known_at")
            )
            to_known_at = (
                args.to_known_at
                or (positional_cuts[1] if len(positional_cuts) >= 2 else None)
                or bundle.get("to_known_at")
                or known_at
            )
            if not issued_at or not from_known_at or not to_known_at:
                raise KeychronicleError(
                    "diff requires --issued-at T, --from-known-at K1 and --to-known-at K2"
                )
            report = diff_knowledge_cuts(
                bundle,
                issued_at,
                from_known_at,
                to_known_at,
                threshold=args.threshold,
            )
            _write_json(report, args.output, compact=args.compact)
            return 0

        parser.error(f"unknown command: {args.command}")
        return 2
    except KeychronicleError as exc:
        sys.stderr.write(f"keychronicle: error: {exc}\n")
        return 2
    except OSError as exc:
        sys.stderr.write(f"keychronicle: file error: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

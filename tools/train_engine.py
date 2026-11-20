"""Offline calibration for the explainable SaaS engine.

This does not replace the rules engine with a black-box model. It learns
metric-specific normal baselines and conservative thresholds from labeled
datasets, exports them as JSON, and the SaaS engine can load the profile.

Supported sources:
- Hugging Face tabular datasets for CICIDS2017 and UNSW-NB15
- Local CSV/Parquet time-series files for NAB and Yahoo
- Local CSV/Parquet Google Cluster Trace exports
"""
import argparse
import json
import os
import statistics
from pathlib import Path

import pandas as pd


LABEL_COLUMNS = ("Label", "label", "attack", "is_attack", "class", "category")


def find_column(columns, candidates):
    lookup = {str(column).strip().lower().replace(" ", "_"): column for column in columns}
    for candidate in candidates:
        key = candidate.lower().replace(" ", "_")
        if key in lookup:
            return lookup[key]
    return None


def numeric_series(frame, candidates):
    column = find_column(frame.columns, candidates)
    if column is None:
        return None
    values = pd.to_numeric(frame[column], errors="coerce").replace([float("inf"), float("-inf")], pd.NA).dropna()
    return values if len(values) else None


def robust_profile(values):
    clean = [float(value) for value in values if float(value) >= 0]
    if not clean:
        return None
    median = statistics.median(clean)
    mad = statistics.median(abs(value - median) for value in clean)
    return {
        "median": round(median, 6),
        "mad": round(max(mad, 0.05 * abs(median), 0.001), 6),
        "p95": round(float(pd.Series(clean).quantile(0.95)), 6),
        "p99": round(float(pd.Series(clean).quantile(0.99)), 6),
        "count": len(clean),
    }


def load_huggingface(dataset_id, split=None):
    from datasets import load_dataset

    if split:
        return load_dataset(dataset_id, split=split).to_pandas()
    dataset = load_dataset(dataset_id)
    frames = [part.to_pandas() for part in dataset.values()]
    return pd.concat(frames, ignore_index=True)


def split_normal_attack(frame):
    label_column = next(
        (
            column
            for column in frame.columns
            if str(column).strip().lower() in LABEL_COLUMNS
        ),
        None,
    )
    if label_column is None:
        label_column = find_column(frame.columns, ("attack", "attack_type", "category", "label"))
    if label_column is None:
        return frame.iloc[0:0], frame

    labels = frame[label_column].astype(str).str.strip().str.lower()
    attack = ~labels.isin(("0", "benign", "normal", "background"))
    return frame.loc[~attack], frame.loc[attack]


def load_tabular(path=None, dataset_id=None):
    if dataset_id:
        return load_huggingface(dataset_id)
    if not path:
        return None
    path = Path(path)
    if path.suffix.lower() in (".parquet", ".pq"):
        return pd.read_parquet(path)
    if path.suffix.lower() in (".csv", ".txt"):
        return pd.read_csv(path)
    raise ValueError(f"Unsupported tabular format: {path}")


def calibration_for(frame, normal=True):
    subset = frame
    mapped = {}
    mappings = {
        "packet_loss": ("packet_loss", "packet loss"),
        "latency": ("tcprtt", "tcp_round_trip_time", "latency", "response_time"),
        "bandwidth": ("Flow Bytes/s", "bytes_per_sec", "bandwidth", "sbytes", "dbytes"),
        "iface_errors": ("errors", "interface_errors", "iface_errors"),
        "cpu": ("cpu_usage", "cpu utilization", "cpu", "cpu_usage_percent"),
        "mem": ("memory_usage", "memory utilization", "mem", "memory_usage_percent"),
        "disk": ("disk_usage", "disk utilization", "disk", "disk_usage_percent"),
        "auth_failures": ("failed_logins", "authentication failures", "auth_failures"),
        "suspicious_activity": ("Suspicious", "anomaly", "suspicious_activity"),
        "api_response_time": ("response_time", "api_response_time"),
        "api_errors": ("api_errors", "error_count"),
        "app_crashes": ("crashes", "app_crashes"),
        "db_query_time": ("db_query_time", "query_duration"),
        "db_connections": ("db_connections", "connections"),
        "deadlocks": ("deadlocks", "deadlock_count"),
    }
    for metric, candidates in mappings.items():
        values = numeric_series(subset, candidates)
        if values is not None:
            profile = robust_profile(values)
            if profile:
                mapped[metric] = profile
    return mapped


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cic-dataset", default="c01dsnap/CIC-IDS2017")
    parser.add_argument("--unsw-dataset", default="wwydmanski/UNSW-NB15")
    parser.add_argument("--nab-file")
    parser.add_argument("--yahoo-file")
    parser.add_argument("--google-file")
    parser.add_argument("--output", default="saas/learned_profiles.json")
    parser.add_argument("--max-rows", type=int, default=250000)
    args = parser.parse_args()

    sources = {}
    for name, dataset_id in (("cicids2017", args.cic_dataset), ("unsw_nb15", args.unsw_dataset)):
        try:
            frame = load_huggingface(dataset_id).head(args.max_rows)
            normal, attack = split_normal_attack(frame)
            sources[name] = {
                "normal": calibration_for(normal),
                "attack": calibration_for(attack),
                "rows_normal": len(normal),
                "rows_attack": len(attack),
                "license_note": "Verify dataset license and terms before redistribution.",
            }
            print(f"{name}: normal={len(normal)} attack={len(attack)}")
        except Exception as error:
            sources[name] = {"error": type(error).__name__, "message": str(error)}
            print(f"{name}: unavailable: {error}")

    for name, path in (("nab", args.nab_file), ("yahoo", args.yahoo_file), ("google_cluster", args.google_file)):
        if not path:
            continue
        frame = load_tabular(path=path)
        if len(frame) > args.max_rows:
            frame = frame.head(args.max_rows)
        sources[name] = {
            "normal": calibration_for(frame),
            "rows": len(frame),
            "source": os.path.abspath(path),
        }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as file:
        json.dump({
            "model": "explainable-median-mad-calibration",
            "sources": sources,
        }, file, indent=2)
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()

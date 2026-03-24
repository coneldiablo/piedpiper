#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor/main.py

Главная точка входа (CLI + GUI) для проекта.
Реализует субкоманды:
  1) gui
  2) static <file>
  3) dynamic <file>
  4) ioc
  5) risk
  6) scan <directory>
  7) report
  8) vt <mode> <arg>

Все операции реально вызывают соответствующие модули:
  - analyzer/static_analysis
  - analyzer/dynamic_analysis
  - analyzer/ioc_extractor
  - analyzer/scoring
  - analyzer/behavioral_analysis
  - core.explorer
  - reports/report_generator
  - core.vt_integration
  - gui.main_gui
"""

import sys
import argparse
import json
import logging
import os
import importlib.util
import time

# ==== ДОБАВЛЕННЫЕ СТРОЧКИ ====
# Отключаем цветной вывод, чтобы избежать ошибки 'NoneType' object has no attribute 'flush'
os.environ["COLOR_DISABLE"] = "1"
# Verbose launch to surface startup/exit codes to console unless explicitly disabled
os.environ.setdefault("THREATINQ_VERBOSE_LAUNCH", "1")
# ============================

# Модули ThreatInquisitor
from analyzer.static_analysis import static_analysis
from analyzer.dynamic_analysis import dynamic_analysis
from analyzer.ioc_extractor import extract_iocs
from analyzer.scoring import calculate_risk
from analyzer.behavioral_analysis import analyze_behavior
from core.explorer import scan_directory
from reports.report_generator import generate_report
from core.vt_integration import VirusTotalClient
from core.config import config_manager
from services.file_monitor import FileMonitorService

# GUI modules are loaded lazily; import costs are high and we want CLI mode to stay fast.


logger = logging.getLogger("main")
logging.basicConfig(level=logging.DEBUG)

PRODUCT_NAME = "Pied Piper"
PRODUCT_FULL_TITLE = (
    "Pied Piper: Integrated multi-level malware analysis system with "
    "AI-assisted classification and threat intelligence automation"
)


def _trace(msg: str) -> None:
    """Append a startup trace line to launch_trace.log for debugging GUI start."""
    try:
        with open("launch_trace.log", "a", encoding="utf-8") as _f:
            _f.write(msg + "\n")
    except Exception:
        pass

def _load_modern_gui():
    """Import the modern PyQt GUI entry point, returning callable or None."""
    try:
        from gui.modern_gui import run_modern_gui  # type: ignore
        return run_modern_gui
    except Exception:
        logger.exception("Modern GUI failed to load.")
        return None


def _load_legacy_gui():
    """Import the legacy GUI entry point, returning callable or None."""
    if importlib.util.find_spec("gui.main_gui") is None:
        logger.debug("Legacy GUI module gui.main_gui not found; skipping fallback.")
        return None
    try:
        from gui.main_gui import run_gui  # type: ignore
        return run_gui
    except Exception:
        logger.exception("Legacy GUI failed to load.")
        return None

def main():
    parser = argparse.ArgumentParser(
        description=PRODUCT_FULL_TITLE
    )
    subparsers = parser.add_subparsers(dest="command")

    # -------------------- GUI ----------------------
    gui_parser = subparsers.add_parser("gui", help="Run PyQt GUI.")
    gui_parser.add_argument(
        "--safe",
        action="store_true",
        help="Force safe GUI startup (Agg backend for matplotlib)",
    )
    gui_parser.add_argument(
        "--diagnose",
        action="store_true",
        help="Diagnose GUI startup and print detailed errors",
    )

    # -------------------- STATIC ----------------------
    static_parser = subparsers.add_parser("static", help="Perform static analysis on a file.")
    static_parser.add_argument("file", help="Path to target file")

    # -------------------- DYNAMIC ----------------------
    dynamic_parser = subparsers.add_parser("dynamic", help="Perform dynamic analysis (Frida) on a file.")
    dynamic_parser.add_argument("file", help="Path to target file")
    dynamic_parser.add_argument("--timeout", type=int, default=15, help="Timeout for analysis in seconds")

    # -------------------- IOC ----------------------
    ioc_parser = subparsers.add_parser("ioc", help="Extract IoCs from JSON with static/dynamic data.")
    ioc_parser.add_argument("--static-json", help="Path to static analysis JSON")
    ioc_parser.add_argument("--dynamic-json", help="Path to dynamic analysis JSON")
    ioc_parser.add_argument("--output", help="Output JSON with IoCs", default="iocs_output.json")

    # -------------------- RISK ----------------------
    risk_parser = subparsers.add_parser("risk", help="Calculate risk score from data.")
    risk_parser.add_argument("--static-json", help="Path to static analysis JSON")
    risk_parser.add_argument("--dynamic-json", help="Path to dynamic analysis JSON")
    risk_parser.add_argument("--ioc-json", help="Path to IoCs JSON")
    risk_parser.add_argument("--vt-json", help="Path to VirusTotal JSON (optional)")
    risk_parser.add_argument("--output", default="risk_output.json", help="Output file for risk")

    # -------------------- SCAN ----------------------
    scan_parser = subparsers.add_parser("scan", help="Scan a directory to find suspicious files.")
    scan_parser.add_argument("directory", help="Directory to scan")
    scan_parser.add_argument("--recursive", action="store_true", default=True, help="Scan subdirectories")
    scan_parser.add_argument("--hashes", action="store_true", help="Compute MD5/SHA256 for each file")
    scan_parser.add_argument("--output", default="scan_output.json", help="Output JSON with results")

    # -------------------- MONITOR ----------------------
    monitor_parser = subparsers.add_parser(
        "monitor", help="Continuously monitor directories for suspicious file activity."
    )
    monitor_parser.add_argument(
        "--paths", nargs="+", help="Directories to monitor (defaults to config MONITORING.paths)"
    )
    monitor_parser.add_argument(
        "--include-ext",
        nargs="+",
        help="Whitelist of file extensions to monitor (e.g. .exe .dll)",
    )
    monitor_parser.add_argument(
        "--exclude",
        nargs="+",
        help="Directories to exclude from monitoring",
    )
    monitor_parser.add_argument(
        "--no-baseline",
        action="store_true",
        help="Skip baseline scan before starting the monitor",
    )
    monitor_parser.add_argument(
        "--duration",
        type=int,
        help="Duration in seconds to run monitoring (default: until interrupted)",
    )
    monitor_parser.add_argument(
        "--summary-json",
        help="Path to export collected monitor summary as JSON upon exit",
    )
    monitor_parser.add_argument(
        "--max-events",
        type=int,
        help="Maximum number of events retained in memory (default from config or 1000)",
    )
    monitor_parser.add_argument(
        "--throttle",
        type=int,
        help="Throttle to N events per minute (0 disables throttling)",
    )

    # -------------------- REPORT ----------------------
    report_parser = subparsers.add_parser("report", help="Generate PDF/HTML report from analysis data.")
    report_parser.add_argument("--static-json", help="Path to static analysis JSON")
    report_parser.add_argument("--dynamic-json", help="Path to dynamic analysis JSON")
    report_parser.add_argument("--ioc-json", help="Path to IoCs JSON")
    report_parser.add_argument("--risk-json", help="Path to risk JSON")
    report_parser.add_argument("--output-dir", default="./reports_out", help="Where to put the PDF/HTML")
    report_parser.add_argument("--base-name", default="PiedPiper_Report", help="Base name for the report files")
    report_parser.add_argument("--logo", help="Path to logo image (optional)")

    # -------------------- VT ----------------------
    vt_parser = subparsers.add_parser("vt", help="Interact with VirusTotal (filehash/url/upload).")
    vt_parser.add_argument("mode", choices=["file", "url", "upload"], help="Which operation? file|url|upload")
    vt_parser.add_argument("value", help="Hash, URL or file path")
    vt_parser.add_argument("--cache", help="Path to JSON cache", default="vt_cache.json")

    args = parser.parse_args()

    # Default to GUI when no subcommand is provided
    if not args.command:
        run_gui = _load_modern_gui()
        if run_gui is None:
            legacy_gui = _load_legacy_gui()
            if legacy_gui is None:
                print("GUI not available. See logs for details.")
                sys.exit(1)
            code = legacy_gui()
            if isinstance(code, int):
                sys.exit(code)
            return
        code = run_gui()
        if isinstance(code, int):
            sys.exit(code)
        return

    # Если нет подкоманд, сразу запускаем GUI
    if not args.command:
        if run_gui is None:
            print("GUI не доступен (PyQt не установлен?).")
            sys.exit(1)
        else:
            sys.exit(run_gui())

    # ============== GUI ==============
    if args.command == "gui":
        # Optional safe mode: prefer Agg to avoid Qt-matplotlib import issues
        if getattr(args, "safe", False) and not os.environ.get("THREATINQ_MPL_MODE"):
            os.environ["THREATINQ_MPL_MODE"] = "agg"
        # Diagnose import/startup in a subprocess if requested
        if getattr(args, "diagnose", False):
            import subprocess, shlex
            env = os.environ.copy()
            env.setdefault("QT_DEBUG_PLUGINS", "1")
            # Ensure pyqtgraph does not trigger import-time crashes during diagnostics
            env.setdefault("THREATINQ_USE_PYQTGRAPH", "0")
            # Default diagnostics to the safe matplotlib backend unless explicitly overridden.
            env.setdefault("THREATINQ_MPL_MODE", env.get("THREATINQ_MPL_MODE", "agg"))
            code = 0
            try:
                print("Running GUI diagnostics (import test)...")
                cmd = [
                    sys.executable,
                    "-X",
                    "dev",
                    "-c",
                    (
                        "import os,sys; print('PY', sys.version); "
                        "print('QT_DEBUG_PLUGINS=', os.environ.get('QT_DEBUG_PLUGINS')); "
                        "print('THREATINQ_MPL_MODE=', os.environ.get('THREATINQ_MPL_MODE')); "
                        "import gui.modern_gui as m; print('modern_gui imported OK'); "
                    ),
                ]
                proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
                code = proc.returncode
                print("--- subprocess stdout:")
                print(proc.stdout)
                print("--- subprocess stderr:")
                print(proc.stderr)
                print(f"[diagnose] subprocess exited with code {code}")
            except Exception as exc:
                print(f"[diagnose] Failed to run diagnostics: {exc}")
                code = 1
            if code != 0:
                sys.exit(code)
        print(f"Launching {PRODUCT_NAME} GUI...")
        _trace(f"[main] Launching {PRODUCT_NAME} GUI...")
        run_gui = _load_modern_gui()
        _trace(f"[main] _load_modern_gui -> {bool(run_gui)}")
        if run_gui:
            try:
                print(f"run_gui resolved to: {run_gui!r}")
                _trace("[main] Calling run_gui()")
            except Exception:
                pass
            try:
                code = run_gui()
                _trace(f"[main] run_gui() returned: {code!r}")
            except Exception as exc:
                logger.exception("Modern GUI crashed on startup: %s", exc)
                print("Modern GUI crashed on startup. See logs for details.")
                _trace(f"[main] Modern GUI crashed: {exc}")
            else:
                if isinstance(code, int):
                    if code != 0:
                        logger.error("Modern GUI exited with code %s; trying legacy GUI.", code)
                        print(f"Modern GUI exited with code {code}; trying legacy GUI...")
                        _trace(f"[main] Modern GUI exited with code {code}")
                    else:
                        print("Modern GUI exited cleanly (code 0).")
                        _trace("[main] Modern GUI exited with code 0")
                        sys.exit(0)
                else:
                    # Non-int result treated as success
                    print("Modern GUI returned non-integer result; treating as success.")
                    _trace("[main] Modern GUI returned non-integer result")
                    return
        print("Falling back to legacy GUI...")
        _trace("[main] Falling back to legacy GUI")
        legacy_gui = _load_legacy_gui()
        if legacy_gui:
            try:
                code = legacy_gui()
                _trace(f"[main] legacy_gui() returned: {code!r}")
            except Exception as exc:
                logger.exception("Legacy GUI crashed on startup: %s", exc)
                print("Legacy GUI crashed on startup. See logs for details.")
                _trace(f"[main] Legacy GUI crashed: {exc}")
                sys.exit(1)
            else:
                if isinstance(code, int):
                    print(f"Legacy GUI exited with code {code}.")
                    sys.exit(code)
                return
        print("GUI not available. See logs for details.")
        _trace("[main] No GUI available")
        sys.exit(1)

    # ============== STATIC ==============
    elif args.command == "static":
        result = static_analysis(args.file)
        out_json = {
            "filepath": args.file,
            "result": result
        }
        out_name = "static_output.json"
        with open(out_name, "w", encoding="utf-8") as f:
            json.dump(out_json, f, indent=2)
        print(f"Static analysis complete. Results saved to {out_name}")

    # ============== DYNAMIC ==============
    elif args.command == "dynamic":
        res = dynamic_analysis(args.file, timeout=args.timeout)
        out_json = {
            "filepath": args.file,
            "result": res
        }
        out_name = "dynamic_output.json"
        with open(out_name, "w", encoding="utf-8") as f:
            json.dump(out_json, f, indent=2)
        print(f"Dynamic analysis complete. Results saved to {out_name}")

    # ============== IOC ==============
    elif args.command == "ioc":
        static_data = {}
        dynamic_data = {}
        if args.static_json and os.path.isfile(args.static_json):
            with open(args.static_json, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if "result" in loaded:
                    static_data = loaded["result"]
        if args.dynamic_json and os.path.isfile(args.dynamic_json):
            with open(args.dynamic_json, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if "result" in loaded:
                    dynamic_data = loaded["result"]

        iocs = extract_iocs(static_data, dynamic_data)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(iocs, f, indent=2)
        print(f"IoCs extracted, saved to {args.output}")

    # ============== RISK ==============
    elif args.command == "risk":
        static_data = {}
        dynamic_data = {}
        ioc_data = []
        vt_data = {}

        if args.static_json and os.path.isfile(args.static_json):
            with open(args.static_json, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if "result" in loaded:
                    static_data = loaded["result"]
        if args.dynamic_json and os.path.isfile(args.dynamic_json):
            with open(args.dynamic_json, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if "result" in loaded:
                    dynamic_data = loaded["result"]
        if args.ioc_json and os.path.isfile(args.ioc_json):
            with open(args.ioc_json, "r", encoding="utf-8") as f:
                ioc_data = json.load(f)
        if args.vt_json and os.path.isfile(args.vt_json):
            with open(args.vt_json, "r", encoding="utf-8") as f:
                vt_data = json.load(f)

        risk_res = calculate_risk(static_data, dynamic_data, ioc_data, vt_data)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(risk_res, f, indent=2)
        print(f"Risk score calculated, saved to {args.output}")

    # ============== SCAN ==============
    elif args.command == "scan":
        scan_res = scan_directory(
            args.directory,
            recursive=args.recursive,
            with_hashes=args.hashes,
            suspicious_rules=True
        )
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(scan_res, f, indent=2)
        print(f"Scan completed. Found {len(scan_res)} files. Results in {args.output}")

    # ============== MONITOR ==============
    elif args.command == "monitor":
        if not FileMonitorService.is_available():
            print(
                "watchdog dependency is not installed. Run 'pip install watchdog' to enable monitoring."
            )
            sys.exit(1)

        monitor_cfg = config_manager.get("MONITORING", {}) or {}
        directories = args.paths or monitor_cfg.get("paths", [])
        if not directories:
            print(
                "No directories provided. Supply --paths or configure MONITORING.paths in config.json."
            )
            sys.exit(1)

        include_ext = args.include_ext or monitor_cfg.get("include_extensions")
        exclude_paths = args.exclude or monitor_cfg.get("exclude_paths")
        max_events = args.max_events or monitor_cfg.get("max_events", 1000)
        throttle_cfg = monitor_cfg.get("throttle_per_minute")
        if args.throttle is not None:
            throttle = args.throttle if args.throttle > 0 else None
        else:
            throttle = throttle_cfg
        baseline_with_hashes = monitor_cfg.get("baseline_with_hashes", True)
        if args.no_baseline:
            baseline_with_hashes = False

        try:
            monitor = FileMonitorService(
                directories=directories,
                include_extensions=include_ext,
                exclude_paths=exclude_paths,
                recursive=monitor_cfg.get("recursive", True),
                baseline_with_hashes=baseline_with_hashes,
                max_events=max_events,
                throttle_per_minute=throttle,
            )
        except Exception as exc:
            print(f"Failed to initialise monitor: {exc}")
            sys.exit(1)

        if baseline_with_hashes:
            baseline = monitor.run_baseline()
            suspicious_baseline = sum(1 for item in baseline if item.get("suspicious"))
            print(
                f"Baseline completed for {len(directories)} paths "
                f"({len(baseline)} files, {suspicious_baseline} suspicious)."
            )

        monitor.start()
        print("Monitoring started. Press Ctrl+C to stop.")

        try:
            if args.duration and args.duration > 0:
                end_time = time.time() + args.duration
                while time.time() < end_time:
                    time.sleep(1)
            else:
                while True:
                    time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping monitor...")
        finally:
            monitor.stop()

        summary = monitor.get_summary()
        print(f"Collected {summary['event_count']} events.")
        if summary["recent_events"]:
            print("Recent events:")
            for event in summary["recent_events"][-5:]:
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event["timestamp"]))
                path = event.get("path")
                action = event.get("action")
                suspicious = event.get("suspicious")
                flag = " suspicious" if suspicious else ""
                print(f"  [{ts}] {action}: {path}{flag}")
        if args.summary_json:
            monitor.export_summary(args.summary_json)
            print(f"Summary exported to {args.summary_json}")

    # ============== REPORT ==============
    elif args.command == "report":
        static_data = {}
        dynamic_data = {}
        ioc_data = []
        risk_data = {}

        if args.static_json and os.path.isfile(args.static_json):
            with open(args.static_json, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if "result" in loaded:
                    static_data = loaded["result"]
        if args.dynamic_json and os.path.isfile(args.dynamic_json):
            with open(args.dynamic_json, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if "result" in loaded:
                    dynamic_data = loaded["result"]
        if args.ioc_json and os.path.isfile(args.ioc_json):
            with open(args.ioc_json, "r", encoding="utf-8") as f:
                ioc_data = json.load(f)
        if args.risk_json and os.path.isfile(args.risk_json):
            with open(args.risk_json, "r", encoding="utf-8") as f:
                risk_data = json.load(f)

        results = generate_report(
            output_dir=args.output_dir,
            base_name=args.base_name,
            static_data=static_data,
            dynamic_data=dynamic_data,
            ioc_data=ioc_data,
            risk_data=risk_data,
            logo_path=args.logo
        )
        print("Report generated: ", results)

    # ============== VT ==============
    elif args.command == "vt":
        vt_api_key = config_manager.get("VIRUSTOTAL_API_KEY", "")
        if not vt_api_key:
            print("No VIRUSTOTAL_API_KEY set in config. Please set it or use environment variable THREATINQ_VT_KEY.")
            sys.exit(1)

        vt = VirusTotalClient(api_key=vt_api_key, use_cache=True, cache_file=args.cache)

        if args.mode == "file":
            info = vt.check_file_hash(args.value)
            out_name = "vt_filehash_result.json"
            with open(out_name, "w", encoding="utf-8") as f:
                json.dump(info, f, indent=2)
            print(f"VirusTotal filehash info saved to {out_name}")

        elif args.mode == "url":
            info = vt.check_url(args.value)
            out_name = "vt_url_result.json"
            with open(out_name, "w", encoding="utf-8") as f:
                json.dump(info, f, indent=2)
            print(f"VirusTotal URL info saved to {out_name}")

        elif args.mode == "upload":
            if not os.path.isfile(args.value):
                print(f"File not found: {args.value}")
                sys.exit(1)
            info = vt.submit_file(args.value)
            out_name = "vt_upload_result.json"
            with open(out_name, "w", encoding="utf-8") as f:
                json.dump(info, f, indent=2)
            print(f"VirusTotal file upload info saved to {out_name}")

    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except SystemExit as _exc:
        # Let SystemExit propagate as the actual exit code
        raise
    except Exception as _exc:
        import traceback
        print("Fatal error on startup:")
        traceback.print_exc()
        sys.exit(1)

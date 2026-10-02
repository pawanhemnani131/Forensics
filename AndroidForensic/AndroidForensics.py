#!/usr/bin/env python3
"""
Android Forensics Tool
Version 1.0

Phases:
1. ADB/device identification
2. Evidence acquisition
3. SHA-256 integrity + acquisition metadata
4.1 Evidence processing/normalization
4.2 Forensic timeline
4.3 Findings/anomaly extraction
5. Forensic PDF report

Design goals:
- Authorized ADB acquisition only; no security bypass.
- Raw evidence is never modified after collection.
- Permission-denied/restricted commands are preserved in their output files.
- Derived processing is kept separate from raw evidence.
"""

import csv
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone

TOOL_NAME = "Android Forensics Tool"
TOOL_VERSION = "1.0"

CASE_DIR = None
DEVICE_SERIAL = None
DEVICE_INFO = {}
COLLECTION_RESULTS = []
TIMELINE_EVENTS = []
FINDINGS = []


def now_iso():
    return datetime.now().astimezone().isoformat()


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def write_text(path, content):
    parent = os.path.dirname(path)
    if parent:
        ensure_dir(parent)
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write(content if content is not None else "")


def write_json(path, data):
    parent = os.path.dirname(path)
    if parent:
        ensure_dir(parent)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False, default=str)


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def run_command(command, timeout=120):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def adb_command(args, timeout=120):
    return run_command(["adb", "-s", DEVICE_SERIAL] + args, timeout)


def rel(path):
    return os.path.relpath(path, CASE_DIR)


def print_section(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def check_adb():
    code, stdout, stderr = run_command(["which", "adb"])
    if code != 0:
        print("ERROR: ADB not found.")
        print("Install with: sudo apt install adb")
        return False
    print(f"ADB found: {stdout.strip()}")
    code, stdout, stderr = run_command(["adb", "version"])
    if stdout.strip():
        print(stdout.strip())
    return True


def start_adb():
    code, stdout, stderr = run_command(["adb", "start-server"])
    if code != 0:
        print("ERROR: Unable to start ADB:")
        print(stderr.strip())
        return False
    print("ADB server running")
    return True


def get_devices():
    code, stdout, stderr = run_command(["adb", "devices"])
    if code != 0:
        return []
    devices = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            devices.append({"serial": parts[0], "state": parts[1]})
    return devices


def select_device():
    global DEVICE_SERIAL
    devices = get_devices()
    print_section("CONNECTED ANDROID DEVICES")
    if not devices:
        print("No Android devices detected.")
        return False
    for d in devices:
        print(f"Serial : {d['serial']}")
        print(f"State  : {d['state']}\n")
    ready = [d for d in devices if d["state"] == "device"]
    if not ready:
        for d in devices:
            if d["state"] == "unauthorized":
                print("Device is UNAUTHORIZED. Accept USB debugging on the phone.")
            elif d["state"] == "offline":
                print("Device is OFFLINE. Reconnect or restart ADB.")
        return False
    if len(ready) == 1:
        DEVICE_SERIAL = ready[0]["serial"]
    else:
        for i, d in enumerate(ready, 1):
            print(f"{i}. {d['serial']}")
        while True:
            try:
                n = int(input("Select device number: "))
                if 1 <= n <= len(ready):
                    DEVICE_SERIAL = ready[n - 1]["serial"]
                    break
            except ValueError:
                pass
            print("Invalid selection.")
    print(f"Selected device: {DEVICE_SERIAL}")
    return True


def get_prop(prop):
    code, stdout, stderr = adb_command(["shell", "getprop", prop])
    return stdout.strip() if code == 0 else ""


def collect_device_info():
    global DEVICE_INFO
    DEVICE_INFO = {
        "manufacturer": get_prop("ro.product.manufacturer"),
        "brand": get_prop("ro.product.brand"),
        "model": get_prop("ro.product.model"),
        "device": get_prop("ro.product.device"),
        "android_version": get_prop("ro.build.version.release"),
        "sdk_version": get_prop("ro.build.version.sdk"),
        "security_patch": get_prop("ro.build.version.security_patch"),
        "build_id": get_prop("ro.build.id"),
        "fingerprint": get_prop("ro.build.fingerprint"),
        "serial": DEVICE_SERIAL,
    }
    print_section("DEVICE INFORMATION")
    for k, v in DEVICE_INFO.items():
        print(f"{k.replace('_', ' ').title():20}: {v}")


def create_case():
    global CASE_DIR
    case_id = "AND-" + datetime.now().strftime("%Y%m%d_%H%M%S")
    desktop = os.path.expanduser("~/Desktop")
    if not os.path.isdir(desktop):
        desktop = os.path.expanduser("~")
    CASE_DIR = os.path.join(desktop, case_id)
    dirs = [
        "01_RAW_EVIDENCE/01_SYSTEM",
        "01_RAW_EVIDENCE/02_NETWORK",
        "01_RAW_EVIDENCE/03_APPLICATIONS",
        "01_RAW_EVIDENCE/04_USER_DATA",
        "01_RAW_EVIDENCE/05_ACTIVITY",
        "01_RAW_EVIDENCE/06_DEVICE",
        "02_PROCESSED/01_DEVICE",
        "02_PROCESSED/02_SYSTEM",
        "02_PROCESSED/03_NETWORK",
        "02_PROCESSED/04_APPLICATIONS",
        "02_PROCESSED/05_USER_DATA",
        "02_PROCESSED/06_ACTIVITY",
        "02_PROCESSED/07_TIMELINE",
        "02_PROCESSED/08_FINDINGS",
        "03_HASHES",
        "04_LOGS",
        "05_BUGREPORT",
        "06_REPORT",
    ]
    for d in dirs:
        ensure_dir(os.path.join(CASE_DIR, d))
    print(f"Case created: {case_id}")
    print(f"Output directory: {CASE_DIR}")


def save_adb_output(name, args, output_path, timeout=120):
    start = time.time()
    code, stdout, stderr = adb_command(args, timeout)
    elapsed = round(time.time() - start, 3)
    content = stdout or ""
    if stderr:
        content += "\n\n===== STDERR =====\n" + stderr
    write_text(output_path, content)
    item = {
        "name": name,
        "path": rel(output_path),
        "return_code": code,
        "success": code == 0,
        "duration_seconds": elapsed,
    }
    COLLECTION_RESULTS.append(item)
    return item


def collect_basic():
    print_section("PHASE 2 - BASIC FORENSIC COLLECTION")
    collectors = [
        ("Battery Information", ["shell", "dumpsys", "battery"], "01_RAW_EVIDENCE/01_SYSTEM/01_battery.txt"),
        ("Memory Information", ["shell", "dumpsys", "meminfo"], "01_RAW_EVIDENCE/01_SYSTEM/02_memory.txt"),
        ("Power Information", ["shell", "dumpsys", "power"], "01_RAW_EVIDENCE/01_SYSTEM/03_power.txt"),
        ("Mounted Storage", ["shell", "dumpsys", "mount"], "01_RAW_EVIDENCE/01_SYSTEM/04_mounted_storage.txt"),
        ("Network Interfaces", ["shell", "ip", "addr"], "01_RAW_EVIDENCE/02_NETWORK/01_interfaces.txt"),
        ("Network Connectivity", ["shell", "dumpsys", "connectivity"], "01_RAW_EVIDENCE/02_NETWORK/02_connectivity.txt"),
        ("Wi-Fi Information", ["shell", "dumpsys", "wifi"], "01_RAW_EVIDENCE/02_NETWORK/03_wifi.txt"),
        ("All Installed Packages", ["shell", "pm", "list", "packages"], "01_RAW_EVIDENCE/03_APPLICATIONS/01_all_packages.txt"),
        ("Third-Party Packages", ["shell", "pm", "list", "packages", "-3"], "01_RAW_EVIDENCE/03_APPLICATIONS/02_third_party_packages.txt"),
    ]
    for i, (name, args, path) in enumerate(collectors, 1):
        print(f"[{i}/{len(collectors)}] {name}")
        r = save_adb_output(name, args, os.path.join(CASE_DIR, path))
        print("    success" if r["success"] else "    failed/restricted")


def collect_advanced():
    print_section("ADVANCED ARTIFACT ACQUISITION")
    collectors = [
        ("System Properties", ["shell", "getprop"], "01_RAW_EVIDENCE/06_DEVICE/01_getprop.txt"),
        ("ADB State", ["shell", "dumpsys", "adb"], "01_RAW_EVIDENCE/06_DEVICE/02_adb_state.txt"),
        ("USB Information", ["shell", "dumpsys", "usb"], "01_RAW_EVIDENCE/06_DEVICE/03_usb.txt"),
        ("Accounts", ["shell", "dumpsys", "account"], "01_RAW_EVIDENCE/04_USER_DATA/01_accounts.txt"),
        ("Persona", ["shell", "dumpsys", "persona"], "01_RAW_EVIDENCE/04_USER_DATA/02_persona.txt"),
        ("Contacts Provider", ["shell", "content", "query", "--uri", "content://contacts/contacts"], "01_RAW_EVIDENCE/04_USER_DATA/03_contacts.txt"),
        ("SMS Inbox", ["shell", "content", "query", "--uri", "content://sms/inbox", "--projection", "_id,address,date,body,type"], "01_RAW_EVIDENCE/04_USER_DATA/04_sms_inbox.txt"),
        ("SMS Sent", ["shell", "content", "query", "--uri", "content://sms/sent", "--projection", "_id,address,date,body,type"], "01_RAW_EVIDENCE/04_USER_DATA/05_sms_sent.txt"),
        ("MMS", ["shell", "content", "query", "--uri", "content://mms", "--projection", "_id,date,msg_box"], "01_RAW_EVIDENCE/04_USER_DATA/06_mms.txt"),
        ("Call Logs", ["shell", "content", "query", "--uri", "content://call_log/calls", "--projection", "_id,number,date,duration,type,name"], "01_RAW_EVIDENCE/04_USER_DATA/07_call_logs.txt"),
        ("Location Service", ["shell", "dumpsys", "location"], "01_RAW_EVIDENCE/05_ACTIVITY/01_location.txt"),
        ("Location Providers", ["shell", "cmd", "location", "providers"], "01_RAW_EVIDENCE/05_ACTIVITY/02_location_providers.txt"),
        ("Notification Service", ["shell", "dumpsys", "notification"], "01_RAW_EVIDENCE/05_ACTIVITY/03_notifications.txt"),
        ("Clipboard Service", ["shell", "dumpsys", "clipboard"], "01_RAW_EVIDENCE/05_ACTIVITY/04_clipboard.txt"),
        ("Window Service", ["shell", "dumpsys", "window"], "01_RAW_EVIDENCE/05_ACTIVITY/05_window.txt"),
        ("Network Statistics", ["shell", "dumpsys", "netstats"], "01_RAW_EVIDENCE/02_NETWORK/04_netstats.txt"),
        ("DropBox Service", ["shell", "dumpsys", "dropbox"], "01_RAW_EVIDENCE/05_ACTIVITY/06_dropbox.txt"),
        ("Battery Statistics", ["shell", "dumpsys", "batterystats"], "01_RAW_EVIDENCE/01_SYSTEM/05_batterystats.txt"),
        ("Stats Service", ["shell", "dumpsys", "stats"], "01_RAW_EVIDENCE/01_SYSTEM/06_stats.txt"),
        ("Sensor Service", ["shell", "dumpsys", "sensorservice"], "01_RAW_EVIDENCE/05_ACTIVITY/07_sensorservice.txt"),
        ("Audio Service", ["shell", "dumpsys", "media.audio_flinger"], "01_RAW_EVIDENCE/05_ACTIVITY/08_audio_flinger.txt"),
        ("Lock Settings", ["shell", "dumpsys", "lock_settings"], "01_RAW_EVIDENCE/06_DEVICE/04_lock_settings.txt"),
        ("Window Focus", ["shell", "dumpsys", "window", "windows"], "01_RAW_EVIDENCE/05_ACTIVITY/10_window_windows.txt"),
    ]
    for i, (name, args, path) in enumerate(collectors, 1):
        print(f"[{i}/{len(collectors)}] {name}")
        r = save_adb_output(name, args, os.path.join(CASE_DIR, path))
        print("    success" if r["success"] else "    failed/restricted")


def collect_logcat():
    print("Collecting logcat snapshot...")
    save_adb_output(
        "Logcat Snapshot",
        ["logcat", "-d"],
        os.path.join(CASE_DIR, "01_RAW_EVIDENCE/05_ACTIVITY/09_logcat.txt"),
        180
    )


def collect_bugreport():
    print("Collecting Android bugreport. This may take several minutes...")
    bugdir = os.path.join(CASE_DIR, "05_BUGREPORT")
    ensure_dir(bugdir)
    code, stdout, stderr = run_command(
        ["adb", "-s", DEVICE_SERIAL, "bugreport", bugdir],
        900
    )
    write_text(
        os.path.join(bugdir, "bugreport_command_output.txt"),
        (stdout or "") + "\n\n===== STDERR =====\n" + (stderr or "")
    )
    print(f"Bugreport return code: {code}")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def hash_raw_evidence():
    print_section("PHASE 3 - EVIDENCE INTEGRITY")
    rawdir = os.path.join(CASE_DIR, "01_RAW_EVIDENCE")
    manifest = []
    for root, dirs, files in os.walk(rawdir):
        for filename in sorted(files):
            path = os.path.join(root, filename)
            try:
                manifest.append({
                    "file": rel(path),
                    "sha256": sha256_file(path),
                    "size_bytes": os.path.getsize(path),
                })
            except Exception as e:
                manifest.append({"file": rel(path), "error": str(e)})
    txt = []
    for item in manifest:
        if "sha256" in item:
            txt.append(f"{item['sha256']}  {item['file']}")
        else:
            txt.append(f"ERROR  {item['file']}  {item['error']}")
    write_text(os.path.join(CASE_DIR, "03_HASHES/01_SHA256_MANIFEST.txt"), "\n".join(txt) + "\n")
    write_json(os.path.join(CASE_DIR, "03_HASHES/02_SHA256_MANIFEST.json"), manifest)
    print(f"Hashed evidence files: {len(manifest)}")
    return manifest


def create_acquisition_metadata(start, end, manifest_count):
    code, stdout, stderr = run_command(["adb", "version"])
    successful = sum(1 for x in COLLECTION_RESULTS if x["success"])
    failed = len(COLLECTION_RESULTS) - successful
    metadata = {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "case_directory": CASE_DIR,
        "device": DEVICE_INFO,
        "adb_version": stdout.strip(),
        "acquisition_start": start,
        "acquisition_end": end,
        "raw_evidence_file_count": manifest_count,
        "collection_summary": {
            "total": len(COLLECTION_RESULTS),
            "successful": successful,
            "failed_or_restricted": failed,
        },
    }
    write_json(os.path.join(CASE_DIR, "06_REPORT/acquisition_metadata.json"), metadata)


def read_text_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def parse_content_provider_rows(content):
    rows = []
    for line in content.splitlines():
        line = line.strip()
        if not line.startswith("Row:"):
            continue
        line = re.sub(r"^Row:\s*\d+\s+", "", line)
        fields = re.split(r",\s*(?=[A-Za-z_][A-Za-z0-9_]*=)", line)
        row = {}
        for field in fields:
            if "=" not in field:
                continue
            key, value = field.split("=", 1)
            row[key.strip()] = value.strip()
        if row:
            rows.append(row)
    return rows


def process_device():
    data = {"source": "device_properties", **DEVICE_INFO}
    write_json(os.path.join(CASE_DIR, "02_PROCESSED/01_DEVICE/device_info.json"), data)
    return data


def process_battery():
    path = os.path.join(CASE_DIR, "01_RAW_EVIDENCE/01_SYSTEM/01_battery.txt")
    if not os.path.exists(path):
        return None
    content = read_text_file(path)
    fields = {}
    patterns = {
        "ac_powered": r"AC powered:\s*(.*)",
        "usb_powered": r"USB powered:\s*(.*)",
        "wireless_powered": r"Wireless powered:\s*(.*)",
        "status": r"status:\s*(.*)",
        "health": r"health:\s*(.*)",
        "level": r"level:\s*(.*)",
        "temperature": r"temperature:\s*(.*)",
        "voltage": r"voltage:\s*(.*)",
        "charge_counter": r"Charge counter:\s*(.*)",
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, content, re.I)
        if m:
            fields[key] = m.group(1).strip()
    data = {"source": rel(path), "battery": fields}
    write_json(os.path.join(CASE_DIR, "02_PROCESSED/02_SYSTEM/battery.json"), data)
    return data


def process_network():
    files = [
        ("interfaces", "01_RAW_EVIDENCE/02_NETWORK/01_interfaces.txt"),
        ("connectivity", "01_RAW_EVIDENCE/02_NETWORK/02_connectivity.txt"),
        ("wifi", "01_RAW_EVIDENCE/02_NETWORK/03_wifi.txt"),
        ("netstats", "01_RAW_EVIDENCE/02_NETWORK/04_netstats.txt"),
    ]
    data = {}
    for name, rpath in files:
        path = os.path.join(CASE_DIR, rpath)
        if os.path.exists(path):
            content = read_text_file(path)
            data[name] = {"source": rpath, "line_count": len(content.splitlines()), "content": content}
    write_json(os.path.join(CASE_DIR, "02_PROCESSED/03_NETWORK/network.json"), data)
    return data


def process_packages():
    result = {"all_packages": [], "third_party_packages": []}
    paths = [
        ("all_packages", "01_RAW_EVIDENCE/03_APPLICATIONS/01_all_packages.txt"),
        ("third_party_packages", "01_RAW_EVIDENCE/03_APPLICATIONS/02_third_party_packages.txt"),
    ]
    for key, rpath in paths:
        path = os.path.join(CASE_DIR, rpath)
        if not os.path.exists(path):
            continue
        for line in read_text_file(path).splitlines():
            line = line.strip()
            if line.startswith("package:"):
                result[key].append(line.split("package:", 1)[1])
    result["counts"] = {k: len(v) for k, v in result.items() if isinstance(v, list)}
    write_json(os.path.join(CASE_DIR, "02_PROCESSED/04_APPLICATIONS/packages.json"), result)
    return result


def process_user_artifacts():
    sms = []
    calls = []
    contacts = []
    for path in glob.glob(os.path.join(CASE_DIR, "01_RAW_EVIDENCE/04_USER_DATA/*.txt")):
        name = os.path.basename(path).lower()
        rows = parse_content_provider_rows(read_text_file(path))
        if "sms" in name:
            sms.extend([{**r, "_source": rel(path)} for r in rows])
        elif "call" in name:
            calls.extend([{**r, "_source": rel(path)} for r in rows])
        elif "contact" in name:
            contacts.extend([{**r, "_source": rel(path)} for r in rows])
    sms_data = {"count": len(sms), "messages": sms}
    call_data = {"count": len(calls), "calls": calls}
    contact_data = {"count": len(contacts), "contacts": contacts}
    write_json(os.path.join(CASE_DIR, "02_PROCESSED/05_USER_DATA/sms.json"), sms_data)
    write_json(os.path.join(CASE_DIR, "02_PROCESSED/05_USER_DATA/call_logs.json"), call_data)
    write_json(os.path.join(CASE_DIR, "02_PROCESSED/05_USER_DATA/contacts.json"), contact_data)
    return {"sms": sms_data, "calls": call_data, "contacts": contact_data}


def process_activity():
    sources = []
    for path in glob.glob(os.path.join(CASE_DIR, "01_RAW_EVIDENCE/05_ACTIVITY/*.txt")):
        content = read_text_file(path)
        sources.append({
            "source": rel(path),
            "line_count": len(content.splitlines()),
            "content": content,
        })
    data = {"sources": sources}
    write_json(os.path.join(CASE_DIR, "02_PROCESSED/06_ACTIVITY/activity.json"), data)
    return data


def process_phase_4_1():
    print_section("PHASE 4.1 - EVIDENCE PROCESSING / NORMALIZATION")
    funcs = [
        ("Device", process_device),
        ("Battery", process_battery),
        ("Network", process_network),
        ("Applications", process_packages),
        ("User Data", process_user_artifacts),
        ("Activity", process_activity),
    ]
    summary = []
    for name, func in funcs:
        print(f"Processing: {name}")
        try:
            result = func()
            status = "SUCCESS" if result is not None else "NO_DATA"
            summary.append({"artifact": name, "status": status})
        except Exception as e:
            summary.append({"artifact": name, "status": "ERROR", "error": str(e)})
            print(f"    ERROR: {e}")
    write_json(os.path.join(CASE_DIR, "02_PROCESSED/processing_summary.json"), summary)


def normalize_timestamp(value):
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    if re.fullmatch(r"\d{10,16}", value):
        try:
            n = int(value)
            ts = n / 1000 if n >= 100000000000 else n
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        except Exception:
            return None
    formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt).isoformat()
        except Exception:
            pass
    return None


def extract_timestamp(text):
    for pattern in [
        r"\b20\d{2}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
        r"\b\d{13}\b",
        r"\b\d{10}\b",
    ]:
        for match in re.findall(pattern, text):
            value = normalize_timestamp(match)
            if value:
                return value
    return None


def add_event(timestamp, event_type, source, description, artifact, confidence="MEDIUM", extra=None):
    if not timestamp:
        return
    event = {
        "timestamp": timestamp,
        "event_type": event_type,
        "source": source,
        "description": description,
        "artifact": artifact,
        "confidence": confidence,
    }
    if extra:
        event.update(extra)
    TIMELINE_EVENTS.append(event)


def build_timeline_from_user_data():
    sms = read_json(os.path.join(CASE_DIR, "02_PROCESSED/05_USER_DATA/sms.json")) or {}
    for row in sms.get("messages", []):
        ts = normalize_timestamp(row.get("date"))
        if ts:
            body = str(row.get("body", "")).replace("\n", " ").strip()
            if len(body) > 240:
                body = body[:240] + "..."
            desc = f"SMS type={row.get('type', 'UNKNOWN')} address={row.get('address', 'UNKNOWN')}"
            if body:
                desc += f" message={body}"
            add_event(ts, "SMS", "SMS", desc, row.get("_source", "SMS"), "HIGH")
    calls = read_json(os.path.join(CASE_DIR, "02_PROCESSED/05_USER_DATA/call_logs.json")) or {}
    for row in calls.get("calls", []):
        ts = normalize_timestamp(row.get("date"))
        if ts:
            desc = f"Call type={row.get('type', 'UNKNOWN')} number={row.get('number', 'UNKNOWN')} duration={row.get('duration', 'UNKNOWN')}s"
            add_event(ts, "CALL", "Call Log", desc, row.get("_source", "Call Log"), "HIGH")


def build_timeline_from_text_artifacts():
    targets = [
        ("LOGCAT", "Android Logcat", "01_RAW_EVIDENCE/05_ACTIVITY/09_logcat.txt", "LOW"),
        ("LOCATION", "Location Service", "01_RAW_EVIDENCE/05_ACTIVITY/01_location.txt", "LOW"),
        ("NOTIFICATION", "Notifications", "01_RAW_EVIDENCE/05_ACTIVITY/03_notifications.txt", "LOW"),
        ("DROPBOX", "DropBox", "01_RAW_EVIDENCE/05_ACTIVITY/06_dropbox.txt", "LOW"),
        ("POWER", "Power Service", "01_RAW_EVIDENCE/01_SYSTEM/03_power.txt", "LOW"),
        ("NETSTATS", "Network Statistics", "01_RAW_EVIDENCE/02_NETWORK/04_netstats.txt", "LOW"),
    ]
    interesting = [
        "sms", "telephony", "location", "gps", "wifi", "bluetooth",
        "package", "activity", "service", "boot", "shutdown", "usb",
        "connect", "disconnect", "notification", "network", "power"
    ]
    for event_type, source, rpath, confidence in targets:
        path = os.path.join(CASE_DIR, rpath)
        if not os.path.exists(path):
            continue
        for line in read_text_file(path).splitlines():
            line = line.strip()
            if not line:
                continue
            ts = extract_timestamp(line)
            if not ts:
                continue
            if event_type == "LOGCAT" and not any(x in line.lower() for x in interesting):
                continue
            add_event(ts, event_type, source, line, rpath, confidence)


def export_timeline():
    unique = {}
    for e in TIMELINE_EVENTS:
        key = (e["timestamp"], e["event_type"], e["source"], e["description"], e["artifact"])
        unique[key] = e
    events = sorted(unique.values(), key=lambda x: x.get("timestamp", ""))
    timeline_dir = os.path.join(CASE_DIR, "02_PROCESSED/07_TIMELINE")
    write_json(os.path.join(timeline_dir, "timeline.json"), {
        "device": DEVICE_INFO,
        "event_count": len(events),
        "events": events,
    })
    with open(os.path.join(timeline_dir, "timeline.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "event_type", "source", "description", "artifact", "confidence"])
        for e in events:
            writer.writerow([e.get("timestamp", ""), e.get("event_type", ""), e.get("source", ""), e.get("description", ""), e.get("artifact", ""), e.get("confidence", "")])
    types = Counter(e.get("event_type", "UNKNOWN") for e in events)
    conf = Counter(e.get("confidence", "UNKNOWN") for e in events)
    summary = {
        "generated_at": now_iso(),
        "event_count": len(events),
        "event_types": dict(types),
        "confidence": dict(conf),
    }
    write_json(os.path.join(timeline_dir, "timeline_summary.json"), summary)
    return events, summary


def build_timeline():
    global TIMELINE_EVENTS
    print_section("PHASE 4.2 - FORENSIC TIMELINE ENGINE")
    TIMELINE_EVENTS = []
    print("Processing user-data timestamps...")
    build_timeline_from_user_data()
    print("Processing timestamped system/activity lines...")
    build_timeline_from_text_artifacts()
    events, summary = export_timeline()
    TIMELINE_EVENTS = events
    print(f"Timeline events: {len(events)}")
    for k, v in sorted(summary["event_types"].items()):
        print(f"  {k:<18} {v}")


def add_finding(severity, category, title, description, evidence=None, confidence="MEDIUM"):
    FINDINGS.append({
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "evidence": evidence or [],
        "confidence": confidence,
    })


def findings_from_collection():
    for item in COLLECTION_RESULTS:
        if not item["success"]:
            add_finding(
                "INFO",
                "Acquisition",
                f"Artifact acquisition restricted/failed: {item['name']}",
                "The command did not return success. The raw output file was retained so the investigator can review the exact response.",
                [item["path"]],
                "HIGH"
            )


def findings_from_device():
    android = DEVICE_INFO.get("android_version", "")
    patch = DEVICE_INFO.get("security_patch", "")
    if android:
        add_finding(
            "INFO", "Device", "Android version identified",
            f"The acquired device reports Android version {android}.",
            ["02_PROCESSED/01_DEVICE/device_info.json"], "HIGH"
        )
    if patch:
        add_finding(
            "INFO", "Device", "Security patch level identified",
            f"The acquired device reports security patch level {patch}.",
            ["02_PROCESSED/01_DEVICE/device_info.json"], "HIGH"
        )


def findings_from_apps():
    data = read_json(os.path.join(CASE_DIR, "02_PROCESSED/04_APPLICATIONS/packages.json")) or {}
    third = data.get("third_party_packages", [])
    if third:
        add_finding(
            "INFO", "Applications", "Third-party application inventory available",
            f"The acquisition contains {len(third)} third-party package entries. This is an inventory for further investigation, not a maliciousness determination.",
            ["02_PROCESSED/04_APPLICATIONS/packages.json"], "HIGH"
        )
    suspicious_terms = ["remote", "rat", "spy", "monitor", "keylog", "tracker", "vpn", "proxy"]
    matches = [p for p in third if any(t in p.lower() for t in suspicious_terms)]
    if matches:
        add_finding(
            "REVIEW", "Applications", "Package names require manual review",
            "Some package names contain generic investigation keywords. Package-name matching alone does not establish malicious activity.",
            matches[:50] + ["02_PROCESSED/04_APPLICATIONS/packages.json"], "LOW"
        )


def findings_from_network():
    path = os.path.join(CASE_DIR, "01_RAW_EVIDENCE/02_NETWORK/01_interfaces.txt")
    content = read_text_file(path)
    ips = sorted(set(re.findall(r"inet\s+(\d+\.\d+\.\d+\.\d+)", content)))
    if ips:
        add_finding(
            "INFO", "Network", "IPv4 interface addresses identified",
            "The interface artifact contains the following IPv4 addresses: " + ", ".join(ips),
            [rel(path)], "HIGH"
        )


def findings_from_user_data():
    sms = read_json(os.path.join(CASE_DIR, "02_PROCESSED/05_USER_DATA/sms.json")) or {}
    calls = read_json(os.path.join(CASE_DIR, "02_PROCESSED/05_USER_DATA/call_logs.json")) or {}
    contacts = read_json(os.path.join(CASE_DIR, "02_PROCESSED/05_USER_DATA/contacts.json")) or {}
    if sms.get("count", 0):
        add_finding("INFO", "User Data", "SMS records acquired", f"{sms['count']} parsed SMS records were produced by the content-provider acquisition.", ["02_PROCESSED/05_USER_DATA/sms.json"], "HIGH")
    if calls.get("count", 0):
        add_finding("INFO", "User Data", "Call-log records acquired", f"{calls['count']} parsed call records were produced by the content-provider acquisition.", ["02_PROCESSED/05_USER_DATA/call_logs.json"], "HIGH")
    if contacts.get("count", 0):
        add_finding("INFO", "User Data", "Contact records acquired", f"{contacts['count']} parsed contact-provider records were produced.", ["02_PROCESSED/05_USER_DATA/contacts.json"], "HIGH")


def build_findings():
    global FINDINGS
    print_section("PHASE 4.3 - FINDINGS / INVESTIGATIVE EXTRACTION")
    FINDINGS = []
    findings_from_collection()
    findings_from_device()
    findings_from_apps()
    findings_from_network()
    findings_from_user_data()
    summary = Counter(f["severity"] for f in FINDINGS)
    data = {
        "generated_at": now_iso(),
        "finding_count": len(FINDINGS),
        "severity_counts": dict(summary),
        "findings": FINDINGS,
    }
    write_json(os.path.join(CASE_DIR, "02_PROCESSED/08_FINDINGS/findings.json"), data)
    write_json(os.path.join(CASE_DIR, "02_PROCESSED/08_FINDINGS/findings_summary.json"), {
        "finding_count": len(FINDINGS),
        "severity_counts": dict(summary),
    })
    print(f"Findings generated: {len(FINDINGS)}")
    for k, v in sorted(summary.items()):
        print(f"  {k:<12} {v}")


def create_logs():
    successful = sum(1 for x in COLLECTION_RESULTS if x["success"])
    failed = len(COLLECTION_RESULTS) - successful
    acquisition_log = [
        f"Tool: {TOOL_NAME}",
        f"Version: {TOOL_VERSION}",
        f"Generated: {now_iso()}",
        f"Device: {DEVICE_SERIAL}",
        "",
        "COLLECTION RESULTS",
    ]
    for x in COLLECTION_RESULTS:
        acquisition_log.append(f"{x['name']} | {'SUCCESS' if x['success'] else 'FAILED/RESTRICTED'} | {x['path']}")
    acquisition_log += ["", f"Successful: {successful}", f"Failed/Restricted: {failed}"]
    write_text(os.path.join(CASE_DIR, "04_LOGS/acquisition.log"), "\n".join(acquisition_log) + "\n")
    processing_log = [
        f"Tool: {TOOL_NAME}",
        f"Version: {TOOL_VERSION}",
        f"Generated: {now_iso()}",
        "Raw evidence was not modified.",
        "Processing, timeline and findings are derived artifacts.",
    ]
    write_text(os.path.join(CASE_DIR, "04_LOGS/processing.log"), "\n".join(processing_log) + "\n")


def create_pdf_report():
    print_section("PHASE 5 - FORENSIC PDF REPORT")
    report_path = os.path.join(CASE_DIR, "06_REPORT/Android_Forensics_Report.pdf")
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    except ImportError:
        print("reportlab is not installed; PDF report was not generated.")
        print("Install with: python3 -m pip install reportlab")
        write_json(os.path.join(CASE_DIR, "06_REPORT/report_generation_status.json"), {
            "status": "NOT_GENERATED",
            "reason": "reportlab not installed",
            "generated_at": now_iso(),
        })
        return False

    doc = SimpleDocTemplate(
        report_path,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )
    styles = getSampleStyleSheet()
    title = ParagraphStyle("TitleCustom", parent=styles["Title"], alignment=TA_CENTER, spaceAfter=12)
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    body = styles["BodyText"]
    body.leading = 14
    story = []

    story.append(Paragraph("Android Forensic Acquisition Report", title))
    story.append(Paragraph(f"Tool: {TOOL_NAME} v{TOOL_VERSION}", body))
    story.append(Paragraph(f"Generated: {now_iso()}", body))
    story.append(Spacer(1, 10))

    story.append(Paragraph("1. Case and Device Information", h1))
    device_rows = [["Field", "Value"]]
    for k, v in DEVICE_INFO.items():
        device_rows.append([k.replace("_", " ").title(), str(v)])
    table = Table(device_rows, colWidths=[55 * mm, 115 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(table)
    story.append(Spacer(1, 12))

    successful = sum(1 for x in COLLECTION_RESULTS if x["success"])
    failed = len(COLLECTION_RESULTS) - successful
    hash_manifest = read_json(os.path.join(CASE_DIR, "03_HASHES/02_SHA256_MANIFEST.json")) or []
    timeline_summary = read_json(os.path.join(CASE_DIR, "02_PROCESSED/07_TIMELINE/timeline_summary.json")) or {}
    findings_data = read_json(os.path.join(CASE_DIR, "02_PROCESSED/08_FINDINGS/findings.json")) or {}

    story.append(Paragraph("2. Acquisition Summary", h1))
    summary_rows = [
        ["Metric", "Value"],
        ["ADB collectors", str(len(COLLECTION_RESULTS))],
        ["Successful", str(successful)],
        ["Failed / restricted", str(failed)],
        ["Raw evidence files hashed", str(len(hash_manifest))],
        ["Timeline events", str(timeline_summary.get("event_count", 0))],
        ["Findings", str(findings_data.get("finding_count", 0))],
    ]
    table = Table(summary_rows, colWidths=[90 * mm, 80 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
    ]))
    story.append(table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("3. Evidence Integrity", h1))
    story.append(Paragraph(
        "SHA-256 hashes were generated for collected raw evidence files. The primary hash manifest is stored separately in the case directory.",
        body
    ))
    story.append(Paragraph("Manifest: 03_HASHES/01_SHA256_MANIFEST.txt", body))
    story.append(Spacer(1, 10))

    story.append(Paragraph("4. Timeline", h1))
    event_types = timeline_summary.get("event_types", {})
    if event_types:
        rows = [["Event Type", "Count"]] + [[str(k), str(v)] for k, v in sorted(event_types.items())]
        table = Table(rows, colWidths=[100 * mm, 70 * mm], repeatRows=1)
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No timestamped timeline events were parsed from the collected artifacts.", body))
    story.append(Paragraph("Full timeline: 02_PROCESSED/07_TIMELINE/timeline.csv", body))
    story.append(Spacer(1, 12))

    story.append(Paragraph("5. Investigative Findings", h1))
    findings = findings_data.get("findings", [])
    if findings:
        for f in findings:
            story.append(Paragraph(
                f"<b>{f.get('severity', '')} - {f.get('title', '')}</b>",
                h2
            ))
            story.append(Paragraph(f.get("description", ""), body))
            evidence = f.get("evidence", [])
            if evidence:
                story.append(Paragraph("Evidence: " + "; ".join(map(str, evidence[:8])), body))
            story.append(Spacer(1, 7))
    else:
        story.append(Paragraph("No findings were generated by the automated extraction layer.", body))

    story.append(PageBreak())
    story.append(Paragraph("6. Acquisition Restrictions and Notes", h1))
    story.append(Paragraph(
        "Android security boundaries may restrict access to some content providers or system services. A failed or restricted acquisition command is retained as evidence of the acquisition result; the tool does not attempt to bypass those controls.",
        body
    ))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Automated findings are investigative leads, not conclusions of malicious activity. Package names, log lines and keyword matches require examiner validation against the underlying raw evidence.",
        body
    ))

    story.append(Paragraph("7. Case Directory", h1))
    story.append(Paragraph(CASE_DIR, body))

    doc.build(story)
    write_json(os.path.join(CASE_DIR, "06_REPORT/report_generation_status.json"), {
        "status": "GENERATED",
        "path": rel(report_path),
        "generated_at": now_iso(),
    })
    print(f"PDF report: {report_path}")
    return True


def final_summary():
    print_section("FINAL FORENSIC SUMMARY")
    success = sum(1 for x in COLLECTION_RESULTS if x["success"])
    failed = len(COLLECTION_RESULTS) - success
    print(f"Device            : {DEVICE_INFO.get('model', '')}")
    print(f"Serial            : {DEVICE_SERIAL}")
    print(f"Collectors        : {len(COLLECTION_RESULTS)}")
    print(f"Successful        : {success}")
    print(f"Failed/Restricted : {failed}")
    print(f"Timeline Events   : {len(TIMELINE_EVENTS)}")
    print(f"Findings          : {len(FINDINGS)}")
    print(f"Case Directory    : {CASE_DIR}")
    print("\nOUTPUTS")
    print(os.path.join(CASE_DIR, "03_HASHES/01_SHA256_MANIFEST.txt"))
    print(os.path.join(CASE_DIR, "02_PROCESSED/07_TIMELINE/timeline.json"))
    print(os.path.join(CASE_DIR, "02_PROCESSED/07_TIMELINE/timeline.csv"))
    print(os.path.join(CASE_DIR, "02_PROCESSED/08_FINDINGS/findings.json"))
    print(os.path.join(CASE_DIR, "06_REPORT/Android_Forensics_Report.pdf"))
    print("\nCOMPLETE")


def main():
    acquisition_start = now_iso()
    print(f"\n{TOOL_NAME}")
    print(f"Version {TOOL_VERSION}")

    if not check_adb():
        return 1
    if not start_adb():
        return 1
    if not select_device():
        return 1

    collect_device_info()
    create_case()

    collect_basic()
    collect_advanced()
    collect_logcat()

    # Bugreport is large and slow. Enable manually when required.
    # collect_bugreport()

    manifest = hash_raw_evidence()
    acquisition_end = now_iso()
    create_acquisition_metadata(acquisition_start, acquisition_end, len(manifest))

    process_phase_4_1()
    build_timeline()
    build_findings()
    create_logs()
    create_pdf_report()
    final_summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())

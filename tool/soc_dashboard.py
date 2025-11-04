# tool/soc_dashboard.py
import sys, os, re, requests, json, time
from collections import Counter, defaultdict
from datetime import datetime
import streamlit as st
from io import StringIO
import pandas as pd
from datetime import datetime

# --- CONFIGURATION (Keys are read from sidebar) ---
SUSPICIOUS_AGENTS = [
    "sqlmap",
    "nmap",
    "hydra",
    "feroxbuster",
    "gobuster",
    "dirb",
    "wget",
    "curl",
    "python-requests",
]

#
# --- BACKGROUND FUNCTIONS (All 3 Parsers + Helpers) ---
#


def parse_apache_line(line):
    """Parses a single log line in Apache Common Log Format."""
    try:
        # Regex for Apache Common Log Format
        log_pattern = re.compile(
            r"(?P<ip>[\d\.]+) - - \[(?P<datetime_str>.*?)\] "
            r'"(?P<request>.*?)" (?P<status_code>\d{3}) '
            r'(?P<size>\d+|-|b".*?") "(.*?)" "(?P<user_agent>.*?)"'
        )
        match = log_pattern.search(line)
        if not match:
            return None
        data = match.groupdict()
        try:
            parts = data["request"].split()
            if len(parts) >= 2:
                data["method"], data["path"] = parts[0], parts[1]
            else:
                data["method"], data["path"] = "UNKNOWN", data["request"]
        except ValueError:
            data["method"], data["path"] = "UNKNOWN", data["request"]
        try:
            data["datetime_obj"] = datetime.strptime(
                data["datetime_str"], "%d/%b/%Y:%H:%M:%S %z"
            )
        except (ValueError, TypeError):
            data["datetime_obj"] = None
        data["suspicious_agent_name"] = next(
            (
                agent
                for agent in SUSPICIOUS_AGENTS
                if agent.lower() in data["user_agent"].lower()
            ),
            None,
        )
        return data
    except Exception:
        return None


def parse_json_line(line):
    """Parses a single log line in the JSON format (from your original access.log)."""
    try:
        json_start_index = line.find("{")
        if json_start_index == -1:
            return None
        json_string = line[json_start_index:]
        log_data = json.loads(json_string)
        data = {
            "ip": log_data.get("remote_addr"),
            "datetime_str": log_data.get("timestamp"),
            "method": log_data.get("method"),
            "path": log_data.get("uri"),
            "status_code": str(log_data.get("status", "000")),
            "user_agent": log_data.get("user_agent", ""),
        }

        # --- DÜZƏLİŞ 1: "Requests Over Time" QRAFİKİ ÜÇÜN ---
        try:
            dt_str = data["datetime_str"]
            # 'Z' (UTC) hərfini '+00:00' ilə əvəz edirik
            if dt_str and dt_str.endswith("Z"):
                dt_str = dt_str[:-1] + "+00:00"
            data["datetime_obj"] = datetime.fromisoformat(dt_str)
        except (ValueError, TypeError):
            data["datetime_obj"] = None
        # --- DÜZƏLİŞ 1-İN SONU ---

        if not all(
            [data["ip"], data["datetime_str"], data["method"], data["status_code"]]
        ):
            return None
        data["suspicious_agent_name"] = next(
            (
                agent
                for agent in SUSPICIOUS_AGENTS
                if agent.lower() in data["user_agent"].lower()
            ),
            None,
        )
        return data
    except Exception:
        return None


def parse_universal_ip_line(line):
    """
    Fallback parser: Finds any IP address in a line, even if the format is unknown.
    This ensures the tool *always* finds IPs and *never* crashes.
    """
    try:
        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        if not ip_match:
            return None

        ip = ip_match.group(1)

        # Fill other fields with 'N/A' to prevent crashes
        data = {
            "ip": ip,
            "datetime_str": "N/A",
            "method": "N/A",
            "path": "N/A",
            "status_code": "N/A",  # This is the source of the 'ValueError'
            "user_agent": line.strip(),
            "datetime_obj": None,
            "suspicious_agent_name": None,
        }

        # Check for suspicious tools in the raw line
        data["suspicious_agent_name"] = next(
            (
                agent
                for agent in SUSPICIOUS_AGENTS
                if agent.lower() in data["user_agent"].lower()
            ),
            None,
        )
        return data

    except Exception:
        return None


def check_abuseipdb_api(ip, api_key):
    """Checks IP reputation using AbuseIPDB API."""
    cti_data = {
        "source": "AbuseIPDB",
        "score": "0%",
        "reports": "0",
        "country": "N/A",
        "error": None,
    }
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=5,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        cti_data["score"] = f"{data.get('abuseConfidenceScore', 0)}%"
        cti_data["reports"] = str(data.get("totalReports", 0))
        cti_data["country"] = data.get("countryCode", "N/A")
        return cti_data
    except requests.exceptions.HTTPError as e:
        cti_data["error"] = f"HTTP Error: {e.response.status_code}. Check API Key."
        return cti_data
    except requests.exceptions.RequestException as e:
        cti_data["error"] = f"Network error: {e}"
        return cti_data


def check_virustotal_api(ip, api_key):
    """Checks IP reputation using VirusTotal API. Fetches Country, Owner, and ASN."""
    cti_data = {
        "source": "VirusTotal",
        "malicious_vendors": "0",
        "country": "N/A",
        "owner": "N/A",
        "asn": "N/A",
        "error": None,
    }
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 429:
            cti_data["error"] = "API rate limit exceeded. Retrying..."
            return cti_data
        response.raise_for_status()
        data = response.json().get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        cti_data["malicious_vendors"] = str(stats.get("malicious", 0))
        cti_data["country"] = attributes.get("country", "N/A")
        cti_data["owner"] = attributes.get("as_owner", "N/A")
        cti_data["asn"] = str(attributes.get("asn", "N/A"))
        return cti_data
    except requests.exceptions.HTTPError as e:
        cti_data["error"] = f"HTTP Error: {e.response.status_code}. Check API Key."
        return cti_data
    except requests.exceptions.RequestException as e:
        cti_data["error"] = f"Network error: {e}"
        return cti_data


@st.cache_data
def get_ip_geolocation(ip):
    """Gets latitude and longitude for an IP address."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data["status"] == "success":
                return data["lat"], data["lon"]
    except requests.exceptions.RequestException:
        return None, None
    return None, None


def get_ai_analyst_note(ip_info, log_container):
    """Generates a placeholder AI analyst note."""
    log_container.info(f"[*] [AI] Generating analyst note for {ip_info['ip']}...")
    detected_agents_list = ip_info["stats"].get("suspicious_agents", [])
    detected_agents_str = (
        ", ".join(detected_agents_list) if detected_agents_list else "None"
    )
    ai_note = f"This IP address ({ip_info['ip']}), associated with '{ip_info['cti']['virustotal_owner']}', is flagged by multiple security vendors "
    if detected_agents_list:
        ai_note += f"and was directly observed using hacking tools like '{detected_agents_str}' to scan our system."
    else:
        ai_note += (
            "and shows a high rate of errors, indicating suspicious automated activity."
        )
    return ai_note


def get_ai_anomaly_report(log_summary, log_container):
    """Generates a placeholder AI anomaly report."""
    log_container.info(f"[*] [AI] Generating general anomaly report...")
    error_ratio = log_summary.get("4xx_errors", 0) / log_summary.get(
        "total_requests", 1
    )
    if error_ratio > 0.05:
        ai_response = f"Anomaly Detected: There is an unusually high ratio of client errors (4xx) ({error_ratio * 100:.1f}%). This pattern suggests a widespread, automated scanning attack."
    else:
        ai_response = "No widespread anomaly detected in status code ratios. Analysis should focus on the high-risk individual IPs identified."
    return ai_response


def analyze_log_file(uploaded_file, log_container, vt_key, abuse_key):
    """
    The main analysis function.
    *** NEW: Auto-detects log format (JSON or Apache) and falls back to Universal. ***
    """
    stringio = StringIO(uploaded_file.getvalue().decode("utf-8"))

    ip_data = defaultdict(
        lambda: {"total_requests": 0, "4xx_errors": 0, "suspicious_agents": set()}
    )
    parsed_lines_list = []
    total_lines = 0
    parsed_lines = 0
    status_code_counts = Counter()

    # --- DÜZƏLİŞ 2: AĞILLI PARSER SEÇİMİ (IndentationError DÜZƏLDİLDİ) ---
    # Əvvəlcə CTF log fayllarını adına görə yoxlayırıq
    if uploaded_file.name in ["ctf_attack_log4shell.log", "ctf_forensics_hijack.log"]:
        parser_func = parse_json_line
        log_container.info(
            f"CTF log file '{uploaded_file.name}' detected. Forcing JSON parser."
        )

    # Əgər CTF faylı deyilsə, universal auto-detect işə düşür
    else:
        log_container.info("Universal file detected. Running auto-detect parser...")
        parser_func = parse_apache_line  # Default
        try:
            # Faylın əvvəlini yoxlamaq üçün stringio.seek(0) etməliyik
            stringio.seek(0)
            first_lines = [stringio.readline() for _ in range(20)]
            stringio.seek(0)  # Faylı tam analiz üçün başa çəkirik

            json_clue_count = 0
            apache_clue_count = 0

            for line in first_lines:
                line = line.strip()
                # Düzəliş: JSON-u tanımaq üçün daha etibarlı yoxlama
                if (
                    line.startswith("{") and line.endswith("}")
                ) or '{"remote_addr":' in line:
                    json_clue_count += 1
                elif re.match(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[", line):
                    apache_clue_count += 1

            if json_clue_count > apache_clue_count:
                parser_func = parse_json_line
                log_container.info("Auto-detected: JSON log format.")
            elif apache_clue_count > json_clue_count:
                parser_func = parse_apache_line
                log_container.info("Auto-detected: Apache log format.")
            else:
                parser_func = parse_universal_ip_line
                log_container.warning(
                    "Could not auto-detect format. Falling back to Universal IP Extractor (limited analysis)."
                )

        except Exception as e:
            log_container.error(
                f"Error during format detection: {e}. Defaulting to Universal IP Extractor."
            )
            stringio.seek(0)
            parser_func = parse_universal_ip_line
    # --- DÜZƏLİŞ 2-NİN SONU ---

    # Faylı təmizlədiyimizdən əmin olmaq üçün (əgər yoxlanıbsa)
    stringio.seek(0)

    for line in stringio.readlines():
        total_lines += 1
        log_entry = parser_func(line)  # Use the detected parser

        if log_entry is None:
            if line.strip() and not line.startswith("#"):
                log_container.warning(
                    f"[!] Malformed log line skipped: {line.strip()[:100]}..."
                )
            continue

        parsed_lines_list.append(log_entry)
        parsed_lines += 1
        ip = log_entry["ip"]
        ip_data[ip]["total_requests"] += 1

        # --- FIX FOR 'N/A' STATUS CODE ---
        status_code_str = log_entry.get("status_code", "N/A")
        if status_code_str.isdigit():
            status_code_int = int(status_code_str)
            if 400 <= status_code_int < 500:
                ip_data[ip]["4xx_errors"] += 1
        status_code_counts[status_code_str] += 1  # This is safe for 'N/A'
        # -----------------------------------

        if log_entry["suspicious_agent_name"]:
            ip_data[ip]["suspicious_agents"].add(log_entry["suspicious_agent_name"])

    log_container.success(
        f"[+] Log file read. {parsed_lines} out of {total_lines} lines successfully parsed."
    )

    if parsed_lines == 0:
        log_container.error(
            f"[!] CRITICAL: No lines were parsed. The file may be empty or in an unsupported format."
        )
        return None, None, None, None, None, None

    unique_ips = list(ip_data.keys())
    log_container.success(f"[+] Total {len(unique_ips)} unique IPs found.")
    all_parsed_df = pd.DataFrame(parsed_lines_list)
    log_summary = {
        "total_requests": parsed_lines,
        "unique_ips": len(unique_ips),
        "4xx_errors": sum(stats["4xx_errors"] for stats in ip_data.values()),
        "status_code_distribution": dict(status_code_counts),
    }

    suspicious_ips_report = []
    suspicious_ip_locations = []
    log_container.info(f"[*] Starting CTI check for {len(unique_ips)} unique IPs...")
    progress_bar = st.progress(0, text="Checking IPs...")

    for i, ip in enumerate(unique_ips):
        progress_bar.progress((i + 1) / len(unique_ips), text=f"Checking: {ip}")
        cti_abuse = check_abuseipdb_api(ip, abuse_key)

        vt_check_count = 0
        while True:
            cti_vt = check_virustotal_api(ip, vt_key)
            vt_check_count += 1
            if (
                cti_vt["error"]
                and "API rate limit exceeded" in cti_vt["error"]
                and vt_check_count < 3
            ):
                log_container.warning(
                    f"  [!] VirusTotal API limit. Sleeping for 15 seconds..."
                )
                time.sleep(15)
            else:
                break

        abuse_score = (
            int(cti_abuse["score"].replace("%", ""))
            if cti_abuse["score"].isdigit()
            else 0
        )
        vt_score = int(cti_vt["malicious_vendors"])
        stats = ip_data[ip]
        has_tools = len(stats["suspicious_agents"]) > 0

        risk = "Medium"
        if (vt_score > 5 and has_tools) or abuse_score == 100 or (vt_score > 10):
            risk = "Critical"
        elif (vt_score > 0 and has_tools) or abuse_score > 50 or vt_score > 5:
            risk = "High"
        is_suspicious = (
            abuse_score > 0 or vt_score > 0 or stats["4xx_errors"] > 0 or has_tools
        )

        if is_suspicious:
            log_container.error(f"[!] Suspicious IP Detected: {ip} (Risk: {risk})")

            lat, lon = get_ip_geolocation(ip)
            if lat and lon:
                suspicious_ip_locations.append(
                    {"ip": ip, "lat": lat, "lon": lon, "risk": risk}
                )

            ip_report_data = {
                "ip": ip,
                "risk": risk,
                "cti": {
                    "abuseipdb_score": cti_abuse["score"],
                    "abuseipdb_reports": cti_abuse["reports"],
                    "virustotal_malicious": cti_vt["malicious_vendors"],
                    "virustotal_country": cti_vt["country"],
                    "virustotal_owner": cti_vt["owner"],
                    "virustotal_asn": cti_vt["asn"],
                    "abuse_error": cti_abuse["error"],
                    "vt_error": cti_vt["error"],
                },
                "stats": {
                    "total_requests": stats["total_requests"],
                    "4xx_errors": stats["4xx_errors"],
                    "suspicious_agents": list(stats["suspicious_agents"]),
                },
            }

            ip_report_data["ai_note"] = get_ai_analyst_note(
                ip_report_data, log_container
            )
            suspicious_ips_report.append(ip_report_data)

    st.empty()  # Clear the main progress bar
    log_container.success(
        f"\n[+] CTI check completed. {len(suspicious_ips_report)} suspicious IPs identified."
    )

    general_ai_note = get_ai_anomaly_report(log_summary, log_container)
    report_string = generate_markdown_report(
        suspicious_ips_report,
        log_summary,
        general_ai_note,
        uploaded_file.name,
        log_container,
    )
    log_summary["suspicious_ips_found"] = len(suspicious_ips_report)

    return (
        log_summary,
        suspicious_ips_report,
        report_string,
        general_ai_note,
        all_parsed_df,
        suspicious_ip_locations,
    )


def generate_markdown_report(
    suspicious_ips, summary, general_ai_note, original_file, log_container
):
    """Generates and saves the Markdown report."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"SOC_Report_{timestamp}.md"

    report_content = f"# SOC Analysis Report - {timestamp}\n\n"
    report_content += f"**Analyzed File:** `{original_file}`\n\n"
    report_content += "## AI General Anomaly Analysis (Bonus)\n\n"
    report_content += f"> {general_ai_note}\n\n"
    report_content += "## General Log Summary\n\n"
    report_content += f"- **Total Parsed Requests:** {summary['total_requests']}\n"
    report_content += f"- **Unique IPs:** {summary['unique_ips']}\n"
    report_content += f"- **Status Code Distribution:** {json.dumps(summary['status_code_distribution'])}\n\n"
    report_content += f"## Suspicious IP Detections ({len(suspicious_ips)})\n\n"

    if not suspicious_ips:
        report_content += "No suspicious IP activity was detected.\n"

    suspicious_ips.sort(key=lambda x: (["Critical", "High", "Medium"].index(x["risk"])))

    for item in suspicious_ips:
        report_content += f"### 🚩 IP: `{item['ip']}` (Risk: {item['risk']})\n\n"
        report_content += f"**AI Analyst Note:** {item['ai_note']}\n\n"
        report_content += "**Enrichment & CTI Data:**\n"

        if item["cti"].get("abuse_error"):
            report_content += (
                f"- **AbuseIPDB Status:** FAILED - {item['cti']['abuse_error']}\n"
            )
        else:
            report_content += f"- **AbuseIPDB Score:** {item['cti']['abuseipdb_score']} (from {item['cti']['abuseipdb_reports']} reports)\n"

        if item["cti"].get("vt_error"):
            report_content += (
                f"- **VirusTotal Status:** FAILED - {item['cti']['vt_error']}\n"
            )
        else:
            report_content += f"- **VirusTotal Detections:** {item['cti']['virustotal_malicious']} vendors\n"
            report_content += (
                f"- **Country (VT):** {item['cti']['virustotal_country']}\n"
            )
            report_content += f"- **Owner (ASN):** {item['cti']['virustotal_owner']} (AS{item['cti']['virustotal_asn']})\n"

        report_content += "\n**Local Statistics:**\n"
        report_content += f"- **Total Requests:** {item['stats']['total_requests']}\n"
        report_content += f"- **4xx Error Count:** {item['stats']['4xx_errors']}\n"
        agents_list = item["stats"].get("suspicious_agents", [])
        agents_str = (
            ", ".join(f"`{agent}`" for agent in agents_list) if agents_list else "NO"
        )
        report_content += f"- **Suspicious Tool(s) Detected:** {agents_str}\n"
        report_content += "---\n\n"

    save_report(filename, report_content, log_container)
    return report_content


def save_report(filename, content, log_container):
    """Saves the report to the 'tool/reports' directory."""
    report_dir = os.path.join(os.path.dirname(__file__), "reports")
    try:
        os.makedirs(report_dir, exist_ok=True)
        file_path = os.path.join(report_dir, filename)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        log_container.success(f"[SUCCESS] Report saved successfully: {file_path}")
    except Exception as e:
        log_container.error(f"[!] ERROR: Failed to save the report: {e}")


# ---
# MAIN INTERFACE FUNCTION (v19 - Final Code Block with ALL Fixes)
# ---


def main_interface():
    st.set_page_config(page_title="SOC Log Analyzer", layout="wide", page_icon="🛡️")
    st.title("🛡️ SOC Log Analysis & CTI Tool")

    st.sidebar.header("🔑 CTI Configuration")
    vt_key = st.sidebar.text_input("VirusTotal API Key", type="password", key="vt_api")
    abuse_key = st.sidebar.text_input(
        "AbuseIPDB API Key", type="password", key="abuse_api"
    )

    if not vt_key or not abuse_key:
        st.warning("Please enter your API keys in the sidebar to begin the analysis.")
        st.session_state.analysis_done = False  # Reset analysis if keys are removed
        return

    st.sidebar.markdown("---")
    st.sidebar.markdown("**Tool Status:** Ready (Keys loaded)")

    col_uploader, col_info = st.columns([2, 1])
    with col_uploader:
        # --- AUTO-DETECT IS NOW THE DEFAULT ---
        uploaded_file = st.file_uploader(
            "Upload your log file (Auto-detects JSON, Apache, or general text)",
            type=["log", "txt"],
        )

    with col_info:
        st.markdown(
            "**Welcome, Analyst!**\n"
            "This tool auto-detects log formats (JSON, Apache, or general text) "
            "to find suspicious IPs and enriches them with CTI data."
        )

    # Initialize session state for analysis results
    if "analysis_done" not in st.session_state:
        st.session_state.analysis_done = False
        st.session_state.all_parsed_df = pd.DataFrame()
        st.session_state.log_summary = {}

    if st.button("Run Analysis", type="primary", use_container_width=True):
        if uploaded_file is not None:
            log_placeholder = st.empty()
            # --- FIX: Removed 'border=True' ---
            log_container = log_placeholder.container()
            log_container.info(
                f"File '{uploaded_file.name}' uploaded. Auto-detecting format and starting analysis..."
            )

            with st.spinner("Analyzing log file... This may take a while..."):
                analysis_results = analyze_log_file(
                    uploaded_file, log_container, vt_key, abuse_key
                )

            if analysis_results and len(analysis_results) == 6:
                (
                    st.session_state.log_summary,
                    st.session_state.suspicious_ips,
                    st.session_state.report_md,
                    st.session_state.ai_anomaly_note,
                    st.session_state.all_parsed_df,
                    st.session_state.suspicious_ip_locations,
                ) = analysis_results
                st.session_state.analysis_done = True
                log_placeholder.empty()
            else:
                st.error(
                    "Analysis failed. Check the logs in the (temp) log container above."
                )
                st.session_state.analysis_done = False
        else:
            st.info("Please upload a log file and click 'Run Analysis'.")

    # Only show tabs *after* analysis is successfully completed
    if st.session_state.analysis_done and not st.session_state.all_parsed_df.empty:
        tab_dashboard, tab_deepdive, tab_explorer = st.tabs(
            [
                "📊 **Dashboard Summary**",
                "🚨 **Suspicious IPs Deep-Dive**",
                "🗂️ **Log Explorer**",
            ]
        )

        # Load data from session state
        log_summary = st.session_state.log_summary
        suspicious_ips = st.session_state.suspicious_ips
        report_md = st.session_state.report_md
        ai_anomaly_note = st.session_state.ai_anomaly_note
        all_parsed_df = st.session_state.all_parsed_df
        suspicious_ip_locations = st.session_state.suspicious_ip_locations

        with tab_dashboard:
            st.subheader("High-Level Summary")
            col1, col2, col3, col4 = st.columns(4)
            total_suspicious = log_summary.get("suspicious_ips_found", 0)
            if total_suspicious >= 3:
                delta_color, color_status = "inverse", "🔴 High Threat"
            elif total_suspicious > 0:
                delta_color, color_status = "off", "🟠 Medium Threat"
            else:
                delta_color, color_status = "normal", "🟢 Low Threat"

            col1.metric("Total Parsed Requests", log_summary.get("total_requests", 0))
            col2.metric("Total Unique IPs", log_summary.get("unique_ips", 0))
            col3.metric(
                "Suspicious IPs Found",
                total_suspicious,
                delta=color_status,
                delta_color=delta_color,
            )
            error_ratio = log_summary.get("4xx_errors", 0) / log_summary.get(
                "total_requests", 1
            )
            col4.metric(
                "4xx Error Ratio",
                f"{error_ratio:.2%}",
                delta=f"{log_summary.get('4xx_errors', 0)} errors",
                delta_color="off",
            )

            st.subheader("AI General Anomaly Analysis")
            st.info(ai_anomaly_note)
            st.divider()

            col_map, col_charts = st.columns(2)
            with col_map:
                st.subheader("Suspicious IP Geolocation")
                if suspicious_ip_locations:
                    df_map = pd.DataFrame(suspicious_ip_locations)
                    df_map["color"] = (
                        df_map["risk"]
                        .map(
                            {
                                "Critical": "#FF0000",
                                "High": "#FFA500",
                                "Medium": "#FFFF00",
                            }
                        )
                        .fillna("#FFFF00")
                    )
                    st.map(
                        df_map,
                        latitude="lat",
                        longitude="lon",
                        size=5000,
                        color="color",
                        zoom=1,
                    )
                else:
                    st.info("No geolocation data available for suspicious IPs.")
            with col_charts:
                st.subheader("Top 10 '404 Not Found' Paths")
                # Ensure 'path' column exists before trying to access it
                if (
                    "path" in all_parsed_df.columns
                    and all_parsed_df["status_code"].dtype == "object"
                ):

                    # --- DÜZƏLİŞ 3: "Top 404" QRAFİKİ ÜÇÜN ---
                    # Status kodunda ola biləcək əlavə boşluqları təmizləmək üçün .str.strip() əlavə edildi
                    df_404s = (
                        all_parsed_df[
                            all_parsed_df["status_code"].str.strip() == "404"
                        ]["path"]
                        .value_counts()
                        .head(10)
                    )
                    # --- DÜZƏLİŞ 3-ÜN SONU ---

                    if not df_404s.empty:
                        st.bar_chart(df_404s, color="#FF4B4B")
                    else:
                        st.success("No '404 Not Found' errors detected.")
                else:
                    st.warning(
                        "Could not generate 'Top 404 Paths' chart. 'path' column not found or status codes are not standard."
                    )

            st.divider()
            st.subheader("Requests Over Time (per Hour)")
            if "datetime_obj" in all_parsed_df.columns:
                df_time = all_parsed_df.dropna(subset=["datetime_obj"])
                if not df_time.empty:
                    df_time = (
                        df_time.set_index("datetime_obj")
                        .resample("H")
                        .size()
                        .reset_index(name="requests")
                    )
                    st.line_chart(
                        df_time, x="datetime_obj", y="requests", color="#00A0FF"
                    )
                else:
                    st.info("No valid timestamps found to plot requests over time.")

        with tab_deepdive:
            st.subheader(f"Suspicious IP Detections ({len(suspicious_ips)})")
            risk_filter = st.selectbox(
                "Filter by Risk Level", ["All", "Critical", "High", "Medium"]
            )
            if not suspicious_ips:
                st.success("No suspicious IP activity was detected.")

            suspicious_ips.sort(
                key=lambda x: (["Critical", "High", "Medium"].index(x["risk"]))
            )
            found_ips_in_filter = 0
            for item in suspicious_ips:
                if risk_filter == "All" or item["risk"] == risk_filter:
                    found_ips_in_filter += 1
                    expander_title = f"IP: `{item['ip']}`  |  Risk: **{item['risk']}** |  Owner: {item['cti']['virustotal_owner']}"
                    if item["risk"] == "Critical":
                        expander = st.expander(
                            f"🔴 CRITICAL | {expander_title}", expanded=True
                        )
                    elif item["risk"] == "High":
                        expander = st.expander(
                            f"🟠 HIGH | {expander_title}", expanded=True
                        )
                    else:
                        expander = st.expander(f"🟡 MEDIUM | {expander_title}")

                    with expander:
                        if item["risk"] == "Critical":
                            st.error(f"**AI Analyst Note:** {item['ai_note']}")
                        elif item["risk"] == "High":
                            st.warning(f"**AI Analyst Note:** {item['ai_note']}")
                        # --- FIX: st_info -> st.info ---
                        else:
                            st.info(f"**AI Analyst Note:** {item['ai_note']}")
                        st.divider()
                        col_cti, col_local = st.columns(2)
                        with col_cti:
                            st.subheader("Enrichment & CTI Data")
                            st.markdown(
                                f"- **AbuseIPDB Status:** {'OK' if not item['cti'].get('abuse_error') else 'FAILED'}"
                            )
                            if not item["cti"].get("abuse_error"):
                                st.markdown(
                                    f"- **AbuseIPDB Score:** `{item['cti']['abuseipdb_score']}` (from {item['cti']['abuseipdb_reports']} reports)"
                                )
                            st.markdown(
                                f"- **VirusTotal Status:** {'OK' if not item['cti'].get('vt_error') else 'FAILED'}"
                            )
                            if not item["cti"].get("vt_error"):
                                st.markdown(
                                    f"- **VirusTotal Detections:** `{item['cti']['virustotal_malicious']}` vendors"
                                )
                                st.markdown(
                                    f"- **Country (VT):** {item['cti']['virustotal_country']}"
                                )
                                st.markdown(
                                    f"- **Owner (ASN):** {item['cti']['virustotal_owner']} (AS{item['cti']['virustotal_asn']})"
                                )
                        with col_local:
                            st.subheader("Local Statistics")
                            agents_list = item["stats"].get("suspicious_agents", [])
                            agents_str = (
                                ", ".join(f"`{agent}`" for agent in agents_list)
                                if agents_list
                                else "NO"
                            )
                            st.markdown(
                                f"- **Total Requests:** `{item['stats']['total_requests']}`\n"
                                f"- **4xx Error Count:** `{item['stats']['4xx_errors']}`\n"
                                f"- **Suspicious Tool(s) Detected:** {agents_str}"
                            )
            if found_ips_in_filter == 0:
                st.info(f"No IPs found matching the risk level '{risk_filter}'.")

        with tab_explorer:
            st.subheader("Interactive Log Explorer (SIEM-style Search)")

            # --- SIEM FILTER (FIXED & ROBUST) ---
            search_query = st.text_input(
                "Universal Search (e.g., '400' or 'nmap' or 'jndi' or 'flag')",
                placeholder="Enter keywords to filter logs...",
                key="siem_search",
            )

            # Start with the full, original dataframe
            filtered_df = all_parsed_df.copy()

            if search_query:
                try:
                    q = search_query.lower()

                    # Convert only relevant columns to string for safe searching
                    df_searchable = all_parsed_df[
                        ["ip", "path", "status_code", "user_agent"]
                    ].astype(str)

                    # Apply a mask across relevant text columns
                    mask = df_searchable.apply(
                        lambda row: row.str.lower().str.contains(q, na=False).any(),
                        axis=1,
                    )

                    filtered_df = all_parsed_df[mask]
                    st.info(
                        f"Found **{len(filtered_df)}** entries matching '{search_query}'."
                    )

                except Exception as e:
                    st.error(f"Search Error: {e}. Please try a different query.")
                    filtered_df = all_parsed_df.copy()  # Reset on error

            columns_to_show = [
                "ip",
                "datetime_str",
                "method",
                "path",
                "status_code",
                "user_agent",
                "suspicious_agent_name",
            ]

            if filtered_df.empty and search_query:
                st.warning(f"No results found for query: '{search_query}'.")
                # Show an empty dataframe with the correct columns
                st.dataframe(
                    filtered_df[columns_to_show], use_container_width=True, height=500
                )
            else:
                st.dataframe(
                    filtered_df[columns_to_show], use_container_width=True, height=500
                )
            # --- END OF SIEM FILTER FIX ---

        st.divider()
        st.download_button(
            label="Download Full Report as Markdown",
            data=report_md,
            file_name="SOC_Report.md",
            mime="text/markdown",
        )


if __name__ == "__main__":
    main_interface()

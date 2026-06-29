import streamlit as st
import subprocess
import os
import datetime
import pandas as pd
from google import genai

# --- Page Configuration ---
st.set_page_config(page_title="Mini SIEM Dashboard", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# --- Custom Styling (Sleek Dark Mode & Alerts) ---
st.markdown("""
<style>
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    .metric-card {
        background-color: #161b22;
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #30363d;
        box-shadow: 0px 4px 6px rgba(0,0,0,0.3);
        height: 100%;
        margin-bottom: 20px;
    }
    .alert-flash {
        animation: blinker 1.5s linear infinite;
        color: white;
        background-color: #a30000;
        padding: 15px;
        border-radius: 8px;
        border: 2px solid red;
        font-weight: bold;
    }
    @keyframes blinker {
        50% { opacity: 0.5; }
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Advanced Mini SIEM & Threat Detection")
st.markdown("#### Hybrid Architecture: x86 Assembly MASM Backend + Python Streamlit Frontend")

# --- File Upload Module ---
uploaded_file = st.file_uploader("Upload Event Log File (.txt)", type=["txt"])

if uploaded_file is not None:
    with open("logs.txt", "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.success("✅ File uploaded and saved locally as 'logs.txt'.")

# --- Execution Block ---
if st.button("Run Threat Analysis", type="primary"):
    if not os.path.exists("logs.txt"):
        st.error("Please upload a log file first before running the analysis.")
    else:
        with st.spinner("Executing low-level x86 Assembly log parsing engine..."):
            try:
                # Call Assembly Executable
                exe_path = os.path.join(os.getcwd(), "Mini_SIEM.exe" if os.name == 'nt' else "Mini_SIEM")
                result = subprocess.run([exe_path], capture_output=True, text=True, timeout=10)
                
                output = result.stdout
                
                if result.returncode != 0 or not output.strip():
                    st.error(f"Error running the backend engine. Ensure '{os.path.basename(exe_path)}' is compiled and located in the root directory.")
                    if result.stderr:
                        st.code(result.stderr)
                else:
                    # Parse Assembly Output into Dictionary
                    metrics = {}
                    for line in output.strip().split('\n'):
                        if ':' in line:
                            key, val = line.split(':', 1)
                            metrics[key.strip()] = val.strip()
                            
                    # Read Raw Logs for Frontend Analytics
                    raw_logs = []
                    with open("logs.txt", "r") as f:
                        raw_logs = f.readlines()
                        
                    log_data = []
                    threat_signatures = ["LOGIN_FAIL", "PORT_SCAN", "PRIV_ESC", "FILE_DELETE"]
                    
                    for log in raw_logs:
                        log = log.strip()
                        if not log: continue
                        status = "🟢 Safe"
                        threat_type = "None"
                        for sig in threat_signatures:
                            if sig in log:
                                status = "🔴 Threat"
                                threat_type = sig
                                break
                        log_data.append({"Log Entry": log, "Status": status, "Threat Type": threat_type})
                        
                    df_logs = pd.DataFrame(log_data)
                            
                    # --- Main Dashboard Layout ---
                    
                    # Row 1: High-level Metrics
                    st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
                    st.subheader("⚙️ Core Engine Metrics Overview")
                    m1, m2, m3, m4, m5, m6 = st.columns(6)
                    m1.metric("Total Logs", metrics.get("TOTAL_LOGS", "0"))
                    m2.metric("Brute Force", metrics.get("BRUTE_FORCE", "0"))
                    m3.metric("Port Scans", metrics.get("PORT_SCANS", "0"))
                    m4.metric("Privilege Esc", metrics.get("PRIV_ESC", "0"))
                    m5.metric("File Tampering", metrics.get("FILE_TAMPERING", "0"))
                    m6.metric("Threat Score", metrics.get("THREAT_SCORE", "0"))
                    st.markdown("</div>", unsafe_allow_html=True)

                    # Row 2: In-Depth Analytics & AI Report
                    col_chart, col_ai = st.columns([1.5, 1])
                    
                    with col_chart:
                        st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
                        st.subheader("📊 In-Depth Analytics (Threat Types)")
                        
                        # Bar chart for threat distribution
                        threat_counts = {
                            "Brute Force (LOGIN_FAIL)": int(metrics.get("BRUTE_FORCE", 0)),
                            "Port Scans (PORT_SCAN)": int(metrics.get("PORT_SCANS", 0)),
                            "Privilege Esc (PRIV_ESC)": int(metrics.get("PRIV_ESC", 0)),
                            "File Tampering (FILE_TAMPERING)": int(metrics.get("FILE_TAMPERING", 0))
                        }
                        
                        df_chart = pd.DataFrame(list(threat_counts.items()), columns=['Threat Type', 'Count'])
                        st.bar_chart(df_chart.set_index('Threat Type'))
                        
                        st.markdown("</div>", unsafe_allow_html=True)
                        
                    with col_ai:
                        st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
                        st.subheader("🤖 AI Incident Report")
                        api_key = os.environ.get("GEMINI_API_KEY")
                        
                        if not api_key:
                            st.warning("⚠️ GEMINI_API_KEY environment variable is missing. Please set it to enable AI report generation.")
                        else:
                            with st.spinner("Generating automated AI Incident Report..."):
                                try:
                                    client = genai.Client(api_key=api_key)
                                prompt = f"""
                                Act as a Senior Cybersecurity Architect. Review the following parsed Mini SIEM metrics and generate a structured Markdown report.
                                It MUST contain exactly these two sections:
                                1. Incident Executive Summary
                                2. 3 Actionable Security Improvements
                                
                                Metrics Data:
                                {metrics}
                                """
                                
                                # Request report from Google GenAI
                                response = client.models.generate_content(
                                    model='gemini-2.5-flash',
                                    contents=prompt,
                                )
                                report_md = response.text
                                
                                # Display and Provide Download Button
                                with st.expander("View Incident Report", expanded=True):
                                    st.markdown(report_md)
                                    
                                st.download_button(
                                    label="Download Incident Report (.md)",
                                    data=report_md,
                                    file_name="incident_report.md",
                                    mime="text/markdown",
                                    type="primary"
                                )
                            except Exception as e:
                                st.error(f"Failed to generate AI report: {e}")
                                st.info("Ensure the API key is correct and has access to Gemini.")
                        st.markdown("</div>", unsafe_allow_html=True)
                        
                    # Row 3: Log Categorization (Good/Bad) & Orchestration
                    col_logs, col_soar = st.columns([1.5, 1])
                    
                    with col_logs:
                        st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
                        st.subheader("📋 Log Flow Categorization (Safe vs. Threat)")
                        st.dataframe(df_logs.tail(1000), use_container_width=True, height=280)
                        st.caption("Showing the last 1000 log entries to optimize browser performance.")
                        st.markdown("</div>", unsafe_allow_html=True)

                    with col_soar:
                        st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
                        st.subheader("🧠 UEBA & SOAR Engine")
                        
                        # UEBA Module Logic
                        brute_force = int(metrics.get("BRUTE_FORCE", 0))
                        st.markdown("#### UEBA Behavioral Analysis")
                        if brute_force > 10:
                            st.markdown("<div class='alert-flash'>🚨 UEBA ALERT: Anomalous volume of failed logins detected against baseline profile. Possible brute-force attack in progress.</div><br>", unsafe_allow_html=True)
                        else:
                            st.success("✅ UEBA: User behavior within normal baseline. No anomalies detected.")
                            
                        # SOAR Module Logic
                        port_scans = int(metrics.get("PORT_SCANS", 0))
                        st.markdown("#### SOAR Automated Responses")
                        if port_scans > 0:
                            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            with open("blocklist.txt", "a") as bf:
                                bf.write(f"[{timestamp}] BLOCKED IPs associated with PORT_SCAN activity.\n")
                            st.warning("⚠️ SOAR Action Triggered: IP addresses automatically appended to firewall blocklist.")
                            st.code(f"Appended to blocklist.txt:\n[{timestamp}] BLOCKED IPs associated with PORT_SCAN activity.")
                        else:
                            st.info("ℹ️ SOAR: No automated actions required.")
                        st.markdown("</div>", unsafe_allow_html=True)
                                
            except FileNotFoundError:
                st.error("❌ Execution failed: 'Mini_SIEM.exe' not found. Ensure you compile the MASM code first and place it in the same directory as this script.")
            except Exception as e:
                st.error(f"❌ An unexpected error occurred: {e}")

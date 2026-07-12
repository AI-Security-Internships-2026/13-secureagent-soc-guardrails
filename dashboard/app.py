

import json
import os
import sys
import time

import pandas as pd
import psutil
import streamlit as st

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.agent.alert_schema import SecurityAlert, SAMPLE_ALERTS
from src.agent.soc_agent import analyse_alert

RESULTS_DIR = "experiments/results"

st.set_page_config(page_title="SecureAgent-SOC", layout="wide")

st.markdown(
    """
    <style>
    .block-container { padding-top: 2rem; padding-bottom: 2rem; }
    div[data-testid="stMetric"] {
        background-color: #161B22;
        border: 1px solid #262C36;
        border-radius: 10px;
        padding: 14px 18px;
    }
    div[data-testid="stMetricLabel"] { color: #9AA4B2; }
    .blocked-banner {
        background-color: #3A1E22;
        border: 1px solid #7A3B42;
        border-radius: 10px;
        padding: 14px 18px;
        color: #F2A6AC;
        font-weight: 600;
    }
    .passed-banner {
        background-color: #1E2E22;
        border: 1px solid #3B7A4C;
        border-radius: 10px;
        padding: 14px 18px;
        color: #9CD6AC;
        font-weight: 600;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("SecureAgent-SOC")


tab_live, tab_results = st.tabs(["Live Demo", "Results Viewer"])


# ---------------------------------------------------------------------------
# Live Demo
# ---------------------------------------------------------------------------
with tab_live:
    left, right = st.columns([1, 1.3], gap="large")

    with left:
        st.subheader("Alert input")

        preset_names = ["Custom"] + [a.alert_id for a in SAMPLE_ALERTS]
        preset = st.selectbox("Load a sample alert", preset_names)

        if preset != "Custom":
            sample = next(a for a in SAMPLE_ALERTS if a.alert_id == preset)
        else:
            sample = None

        alert_id = st.text_input("Alert ID", value=sample.alert_id if sample else "ALERT-CUSTOM")
        severity = st.selectbox(
            "Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            index=["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(sample.severity) if sample else 2,
        )
        source_ip = st.text_input("Source IP", value=sample.source_ip if sample else "10.0.0.1")
        destination_ip = st.text_input("Destination IP", value=sample.destination_ip if sample else "10.0.0.2")
        event_type = st.text_input("Event type", value=sample.event_type if sample else "SUSPICIOUS_ACTIVITY")
        description = st.text_area(
            "Description", value=sample.description if sample else "",
            height=100,
        )
        protocol = st.text_input("Protocol", value=(sample.protocol or "") if sample else "TCP")
        port_val = st.text_input("Port", value=str(sample.port) if sample and sample.port is not None else "")
        payload_snippet = st.text_area(
            "Payload snippet", value=(sample.payload_snippet or "") if sample else "",
            height=80,
        )

        analyze_clicked = st.button("Analyze alert", type="primary", use_container_width=True)

    with right:
        st.subheader("Result")

        if analyze_clicked:
            try:
                port = int(port_val) if port_val.strip() else None
            except ValueError:
                port = None

            alert = SecurityAlert(
                alert_id=alert_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                severity=severity,
                source_ip=source_ip,
                destination_ip=destination_ip,
                event_type=event_type,
                description=description,
                protocol=protocol or None,
                port=port,
                payload_snippet=payload_snippet or None,
            )

            cpu_before = psutil.cpu_percent(interval=None)
            start = time.perf_counter()
            with st.spinner("Running guardrail and agent..."):
                report = analyse_alert(alert)
            elapsed = time.perf_counter() - start
            cpu_after = psutil.cpu_percent(interval=None)

            if report.get("guardrail_blocked"):
                st.markdown(
                    '<div class="blocked-banner">Blocked by guardrail — potential prompt injection detected</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    '<div class="passed-banner">Passed guardrail — analyzed by LLM</div>',
                    unsafe_allow_html=True,
                )

            m1, m2, m3 = st.columns(3)
            m1.metric("Processing time", f"{elapsed * 1000:.0f} ms")
            m2.metric("Severity assessment", report.get("severity_assessment", "N/A"))
            m3.metric("Confidence", f"{report.get('confidence_score', 0):.2f}")

            with st.container(border=True):
                st.markdown(f"**Threat type:** {report.get('threat_type', 'N/A')}")
                st.markdown(f"**Summary:** {report.get('threat_summary', 'N/A')}")
                st.markdown(f"**Recommended action:** {report.get('recommended_action', 'N/A')}")
                st.markdown(f"**Reasoning:** {report.get('reasoning', 'N/A')}")

            with st.expander("Raw report JSON"):
                st.json(report)
        else:
            st.info("Fill in or load an alert on the left, then click Analyze.")


# ---------------------------------------------------------------------------
# Results Viewer
# ---------------------------------------------------------------------------
with tab_results:

    def load_json(filename):
        path = os.path.join(RESULTS_DIR, filename)
        if not os.path.exists(path):
            return None
        with open(path) as f:
            return json.load(f)

    guardrail_results = load_json("guardrail_results.json")
    cicids_results = load_json("cicids2017_results.json")
    fp_results = load_json("fp_rate_results.json")
    threading_results = load_json("threading_benchmark_results.json")

    st.subheader("Summary")

    c1, c2, c3, c4 = st.columns(4)

    if guardrail_results is not None:
        blocked = sum(1 for r in guardrail_results if r.get("guardrail_blocked"))
        c1.metric("Synthetic alerts tested", len(guardrail_results), f"{blocked} blocked")
    else:
        c1.metric("Synthetic alerts tested", "—")

    if cicids_results is not None:
        blocked = sum(1 for r in cicids_results if r.get("guardrail_blocked"))
        c2.metric("Real (CICIDS2017) alerts tested", len(cicids_results), f"{blocked} blocked")
    else:
        c2.metric("Real (CICIDS2017) alerts tested", "—")

    if fp_results is not None:
        c3.metric("False positive rate", f"{fp_results['false_positive_rate']:.1%}",
                   f"{fp_results['false_positives']}/{fp_results['total_tested']} wrongly blocked")
    else:
        c3.metric("False positive rate", "—")

    if threading_results is not None:
        best = max(threading_results["full_pipeline"], key=lambda r: r["throughput_per_sec"])
        c4.metric("Best pipeline throughput", f"{best['throughput_per_sec']:.2f} alerts/sec",
                   f"at {best['num_threads']} threads")
    else:
        c4.metric("Best pipeline throughput", "—")

    st.divider()

    st.subheader("Threading benchmark")
    chart_path = os.path.join(RESULTS_DIR, "visualizations", "threading_benchmark_charts.png")
    if os.path.exists(chart_path):
        st.image(chart_path, use_container_width=True)
    else:
        st.warning(
            "Chart not found. Run: python -m experiments.evaluation.visualize_results"
        )

    if threading_results is not None:
        gcol, pcol = st.columns(2)
        with gcol:
            st.markdown("**Guardrail-only**")
            st.dataframe(pd.DataFrame(threading_results["guardrail_only"]), hide_index=True, use_container_width=True)
        with pcol:
            st.markdown("**Full pipeline**")
            st.dataframe(pd.DataFrame(threading_results["full_pipeline"]), hide_index=True, use_container_width=True)

    st.divider()

    st.subheader("Alert results")
    view_choice = st.radio("Source", ["Synthetic (week 4)", "CICIDS2017 (real)", "False positive test"], horizontal=True)

    if view_choice == "Synthetic (week 4)" and guardrail_results is not None:
        st.dataframe(pd.DataFrame(guardrail_results), hide_index=True, use_container_width=True)
    elif view_choice == "CICIDS2017 (real)" and cicids_results is not None:
        st.dataframe(pd.DataFrame(cicids_results), hide_index=True, use_container_width=True)
    elif view_choice == "False positive test" and fp_results is not None:
        st.dataframe(pd.DataFrame(fp_results["results"]), hide_index=True, use_container_width=True)
    else:
        st.info("No saved results found for this source yet — run the corresponding script first.")
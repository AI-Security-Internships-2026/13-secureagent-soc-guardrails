"""
    streamlit run dashboard/app.py
"""

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
from src.data.load_cicids2017 import load_cicids2017_alerts
from experiments.evaluation.cve_bait_alerts import CVE_BAIT_ALERTS

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
    .guardrail-flag-banner {
        background-color: #3A2E1E;
        border: 1px solid #7A5F3B;
        border-radius: 10px;
        padding: 14px 18px;
        color: #F2CE9A;
        font-weight: 600;
        margin-top: 10px;
    }
    .guardrail-clean-banner {
        background-color: #161B22;
        border: 1px solid #262C36;
        border-radius: 10px;
        padding: 14px 18px;
        color: #9AA4B2;
        margin-top: 10px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("SecureAgent-SOC")


tab_live, tab_results = st.tabs(["Live Demo", "Results Viewer"])


with tab_live:
    left, right = st.columns([1, 1.3], gap="large")

    with left:
        st.subheader("Alert input")

        source_choice = st.radio(
            "Alert source",
            ["Synthetic samples", "CICIDS2017", "CVE-bait (output guardrail demo)", "Custom"],
            horizontal=True,
        )

        sample = None

        if source_choice == "Synthetic samples":
            preset_names = [a.alert_id for a in SAMPLE_ALERTS]
            preset = st.selectbox("Pick a sample alert", preset_names)
            sample = next(a for a in SAMPLE_ALERTS if a.alert_id == preset)

        elif source_choice == "CVE-bait (output guardrail demo)":
            st.caption(
                "Alerts worded to test the output guardrail — BAIT-006 directly "
                "asks for a CVE citation and is the most likely to trigger a "
                "flag. Others describe vulnerabilities by symptom only."
            )
            preset_names = [f"{a.alert_id} ({a.event_type})" for a in CVE_BAIT_ALERTS]
            choice_idx = st.selectbox(
                "Pick a bait alert", range(len(CVE_BAIT_ALERTS)),
                format_func=lambda i: preset_names[i],
                index=len(CVE_BAIT_ALERTS) - 1,  # defaults to BAIT-006
            )
            sample = CVE_BAIT_ALERTS[choice_idx]

        elif source_choice == "CICIDS2017":
            csv_path = st.text_input(
                "CICIDS2017 CSV path",
                value="datasets/cicids2017/Tuesday-WorkingHours.pcap_ISCX.csv",
                help="Any CICIDS2017 daily CSV. Tuesday's file has FTP/SSH brute force.",
            )
            n_to_load = st.slider("Rows to sample", 5, 50, 15)
            seed = st.number_input("Shuffle seed", value=42, step=1)

            if st.button("Load real alerts from CSV"):
                try:
                    loaded = load_cicids2017_alerts(csv_path, n=n_to_load, shuffle=True, seed=int(seed))
                    st.session_state["cicids_loaded"] = loaded
                except FileNotFoundError:
                    st.error(f"File not found: {csv_path}")
                    st.session_state["cicids_loaded"] = []

            loaded = st.session_state.get("cicids_loaded", [])
            if loaded:
                preset_names = [f"{a.alert_id} ({a.event_type})" for a in loaded]
                choice_idx = st.selectbox("Pick a loaded alert", range(len(loaded)), format_func=lambda i: preset_names[i])
                sample = loaded[choice_idx]
            else:
                st.info("Load a CSV above to pick from real alerts.")

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
        user = st.text_input("User", value=(sample.user or "") if sample else "")
        hostname = st.text_input("Hostname", value=(sample.hostname or "") if sample else "")
        file_hash = st.text_input("File hash", value=(sample.file_hash or "") if sample else "")

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
                user=user or None,
                hostname=hostname or None,
                file_hash=file_hash or None,
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

            # Output guardrail: hallucinated CVE + ATT&CK technique check.
            # Only meaningful once the alert actually reached the LLM — an
            # input-blocked alert never produced a report, so there's
            # nothing to check there. Both checkers set requires_review=True
            # for every ungrounded citation regardless of classification
            # tier (see output_guardrail.py / attack_grounding.py), so this
            # banner reflects that directly rather than re-deriving its own
            # notion of "clean" from the classification.
            hallucinated_cves = report.get("hallucinated_cves", [])
            hallucinated_attack_techniques = report.get("hallucinated_attack_techniques", [])
            if not report.get("guardrail_blocked"):
                if not hallucinated_cves and not hallucinated_attack_techniques:
                    st.markdown(
                        '<div class="guardrail-clean-banner">Output guardrail: no ungrounded CVE or '
                        'ATT&CK technique citations detected</div>',
                        unsafe_allow_html=True,
                    )
                else:
                    citation_tags = [
                        f"{v['cve_id']} ({v['classification']})" for v in report.get("cve_verifications", [])
                    ] + [
                        f"{v['technique_id']} ({v['classification']})"
                        for v in report.get("attack_technique_verifications", [])
                    ]
                    total = len(hallucinated_cves) + len(hallucinated_attack_techniques)
                    st.markdown(
                        f'<div class="guardrail-flag-banner">Requires review — {total} citation(s) not grounded '
                        f'in the input alert: {", ".join(citation_tags)}</div>',
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


with tab_results:

    def load_json(filename):
        path = os.path.join(RESULTS_DIR, filename)
        if not os.path.exists(path):
            return None
        with open(path) as f:
            return json.load(f)

    def flatten_benchmark_rows(rows):
        """
        Benchmark results are aggregates over N repeats — each numeric
        measurement is a {"mean", "median", "stdev", "min", "max"} dict
        rather than a single number, plus a "raw_runs" list of the
        individual repeats. Flatten to one mean/stdev column pair per
        measurement for display; drop raw_runs (it's in the underlying
        JSON for reproducibility, not meant for the summary table).
        """
        flat_rows = []
        for row in rows:
            flat = {}
            for k, v in row.items():
                if k == "raw_runs":
                    continue
                if isinstance(v, dict) and "mean" in v:
                    flat[f"{k}_mean"] = v["mean"]
                    flat[f"{k}_stdev"] = v["stdev"]
                else:
                    flat[k] = v
            flat_rows.append(flat)
        return flat_rows

    guardrail_results = load_json("guardrail_results.json")
    cicids_results = load_json("cicids2017_results.json")
    fp_results = load_json("fp_rate_results.json")
    threading_results = load_json("threading_benchmark_results.json")
    mp_results = load_json("multiprocessing_benchmark_results.json")
    cve_bait_results = load_json("cve_bait_results.json")

    st.subheader("Summary")

    c1, c2, c3, c4, c5 = st.columns(5)

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
        best = max(threading_results["full_pipeline"], key=lambda r: r["throughput_per_sec"]["mean"])
        c4.metric("Best pipeline throughput", f"{best['throughput_per_sec']['mean']:.2f} alerts/sec",
                   f"at {best['num_threads']} threads (± {best['throughput_per_sec']['stdev']:.2f}, n={best.get('repeats', 1)})")
    else:
        c4.metric("Best pipeline throughput", "—")

    if cve_bait_results is not None:
        c5.metric("CVE citations requiring review", f"{cve_bait_results['requires_review_rate']:.1%}",
                   f"{cve_bait_results['ungrounded_count']}/{cve_bait_results['total_tested']} ungrounded citation(s)")
    else:
        c5.metric("CVE hallucination rate", "—")

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
            st.dataframe(pd.DataFrame(flatten_benchmark_rows(threading_results["guardrail_only"])),
                         hide_index=True, use_container_width=True)
        with pcol:
            st.markdown("**Full pipeline**")
            st.dataframe(pd.DataFrame(flatten_benchmark_rows(threading_results["full_pipeline"])),
                         hide_index=True, use_container_width=True)

    st.divider()

    st.subheader("Threading vs Multiprocessing")
    st.caption(
        "Multiprocessing sidesteps the GIL entirely (separate interpreters, no shared "
        "lock) but pays for it in process-startup and inter-process data transfer cost. "
        "For the guardrail-only workload — microsecond-scale, no I/O wait — that overhead "
        "dominates completely. For the full pipeline, threading wins because the Groq API "
        "client is created once and shared across threads; multiprocessing re-creates it "
        "in every process, paying connection setup repeatedly instead of once."
    )
    comparison_chart_path = os.path.join(RESULTS_DIR, "visualizations", "concurrency_comparison_charts.png")
    if os.path.exists(comparison_chart_path):
        st.image(comparison_chart_path, use_container_width=True)
    else:
        st.warning(
            "Chart not found. Run: python -m experiments.evaluation.visualize_concurrency_comparison"
        )

    if mp_results is not None:
        gcol, pcol = st.columns(2)
        with gcol:
            st.markdown("**Guardrail-only (multiprocessing)**")
            st.dataframe(pd.DataFrame(flatten_benchmark_rows(mp_results["guardrail_only"])),
                         hide_index=True, use_container_width=True)
        with pcol:
            st.markdown("**Full pipeline (multiprocessing)**")
            st.dataframe(pd.DataFrame(flatten_benchmark_rows(mp_results["full_pipeline"])),
                         hide_index=True, use_container_width=True)
    else:
        st.info("No multiprocessing results found yet — run: python -m experiments.evaluation.multiprocessing_benchmark")

    st.divider()

    st.subheader("Output guardrail — CVE hallucination test")
    if cve_bait_results is not None:
        st.dataframe(
            pd.DataFrame(cve_bait_results["results"])[
                ["alert_id", "severity_assessment", "threat_type", "hallucinated_cves", "requires_review"]
            ],
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.info("No CVE-bait results found yet — run: python -m experiments.evaluation.cve_bait_test")

    st.divider()

    st.subheader("Alert results")
    view_choice = st.radio(
        "Source",
        ["Synthetic (week 4)", "CICIDS2017 (real)", "False positive test", "CVE bait test"],
        horizontal=True,
    )

    if view_choice == "Synthetic (week 4)" and guardrail_results is not None:
        st.dataframe(pd.DataFrame(guardrail_results), hide_index=True, use_container_width=True)
    elif view_choice == "CICIDS2017 (real)" and cicids_results is not None:
        st.dataframe(pd.DataFrame(cicids_results), hide_index=True, use_container_width=True)
    elif view_choice == "False positive test" and fp_results is not None:
        st.dataframe(pd.DataFrame(fp_results["results"]), hide_index=True, use_container_width=True)
    elif view_choice == "CVE bait test" and cve_bait_results is not None:
        st.dataframe(pd.DataFrame(cve_bait_results["results"]), hide_index=True, use_container_width=True)
    else:
        st.info("No saved results found for this source yet — run the corresponding script first.")
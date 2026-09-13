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
from experiments.evaluation.attack_bait_alerts import ATTACK_BAIT_ALERTS

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


tab_live, tab_feed, tab_results = st.tabs(["Live Demo", "Live Feed", "Results Viewer"])


with tab_live:
    left, right = st.columns([1, 1.3], gap="large")

    with left:
        st.subheader("Alert input")

        source_choice = st.radio(
            "Alert source",
            ["Synthetic samples", "CICIDS2017", "CVE-bait (output guardrail demo)",
             "ATT&CK-bait (output guardrail demo)", "Secure_SOC_AI incidents",
             "Wazuh (live)", "Custom"],
            horizontal=True,
        )

        sample = None

        if source_choice == "Synthetic samples":
            preset_names = [a.alert_id for a in SAMPLE_ALERTS]
            preset = st.selectbox("Pick a sample alert", preset_names)
            sample = next(a for a in SAMPLE_ALERTS if a.alert_id == preset)

        elif source_choice == "CVE-bait (output guardrail demo)":
            st.caption(
                "100 alerts describing real vulnerabilities by symptom only, never by "
                "CVE number — 97 never mention a CVE at all (0/97 ever produced an "
                "ungrounded citation in testing); BAIT-002, 011, and 017 explicitly ask "
                "the model to cite one it wasn't given. Defaults to BAIT-017, which "
                "cited a real but wrong CVE (DogWalk instead of the correct Follina) — "
                "the most illustrative flagged example."
            )
            preset_names = [f"{a.alert_id} ({a.event_type})" for a in CVE_BAIT_ALERTS]
            default_idx = next((i for i, a in enumerate(CVE_BAIT_ALERTS) if a.alert_id == "BAIT-017"), 0)
            choice_idx = st.selectbox(
                "Pick a bait alert", range(len(CVE_BAIT_ALERTS)),
                format_func=lambda i: preset_names[i],
                index=default_idx,
            )
            sample = CVE_BAIT_ALERTS[choice_idx]

        elif source_choice == "ATT&CK-bait (output guardrail demo)":
            st.caption(
                "6 alerts describing MITRE ATT&CK technique behavior by symptom only. "
                "Defaults to ATTACK-BAIT-005, which cited T1216 (System Script Proxy "
                "Execution) for what was actually RDP lateral movement with stolen "
                "credentials — a real technique ID, just the wrong one."
            )
            preset_names = [f"{a.alert_id} ({a.event_type})" for a in ATTACK_BAIT_ALERTS]
            default_idx = next((i for i, a in enumerate(ATTACK_BAIT_ALERTS) if a.alert_id == "ATTACK-BAIT-005"), 0)
            choice_idx = st.selectbox(
                "Pick a bait alert", range(len(ATTACK_BAIT_ALERTS)),
                format_func=lambda i: preset_names[i],
                index=default_idx,
            )
            sample = ATTACK_BAIT_ALERTS[choice_idx]

        elif source_choice == "Secure_SOC_AI incidents":
            st.caption(
                "Incidents from Secure_SOC_AI's own rule engine + correlator (76 incidents "
                "generated from synthetic_events.jsonl), not hand-authored. "
                "See docs/INTEGRATION_PLAN.md."
            )
            if st.button("Load incidents"):
                from secure_soc_ai.correlate import Correlator
                from secure_soc_ai.detect.rule_engine import RuleEngine
                from secure_soc_ai.ingest.jsonl_source import JsonlFileSource
                from experiments.evaluation.soc_integration_test import (
                    EVENTS_PATH, RULES_DIR, incident_to_security_alert,
                )

                rules = RuleEngine.from_directory(RULES_DIR)
                correlator = Correlator()
                incidents = {}
                for event in JsonlFileSource(EVENTS_PATH).read():
                    for alert in rules.evaluate(event):
                        incident, _ = correlator.process(alert)
                        if incident is not None:
                            incidents[incident.id] = incident
                for incident in correlator.flush_stale():
                    incidents[incident.id] = incident
                ordered = sorted(incidents.values(), key=lambda i: i.created_at)
                st.session_state["soc_incidents_loaded"] = [incident_to_security_alert(i) for i in ordered]

            loaded = st.session_state.get("soc_incidents_loaded", [])
            if loaded:
                preset_names = [f"{a.alert_id} ({a.event_type})" for a in loaded]
                choice_idx = st.selectbox("Pick an incident", range(len(loaded)), format_func=lambda i: preset_names[i])
                sample = loaded[choice_idx]
            else:
                st.info("Click 'Load incidents' to generate them from the rule engine.")

        elif source_choice == "Wazuh (live)":
            st.caption(
                "Pulls real alerts from a running local Wazuh agent (Docker, local-only) — "
                "requires the stack to be up. See docs/ROADMAP_PLAN.md §10a."
            )
            if st.button("Fetch new alerts from Wazuh"):
                from requests.exceptions import RequestException
                from experiments.evaluation.wazuh_integration_test import (
                    dedupe_alerts, fetch_recent_alerts, wazuh_alert_to_security_alert,
                )
                try:
                    docs = dedupe_alerts(fetch_recent_alerts())
                    st.session_state["wazuh_loaded"] = [wazuh_alert_to_security_alert(d) for d in docs]
                except RequestException as e:
                    st.error(f"Could not reach the Wazuh indexer — is the Docker stack running? ({e})")
                    st.session_state["wazuh_loaded"] = []

            loaded = st.session_state.get("wazuh_loaded", [])
            if loaded:
                preset_names = [f"{a.alert_id} ({a.event_type})" for a in loaded]
                choice_idx = st.selectbox("Pick a live alert", range(len(loaded)), format_func=lambda i: preset_names[i])
                sample = loaded[choice_idx]
            else:
                st.info("Click 'Fetch new alerts from Wazuh' to pull the latest from the indexer.")

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


with tab_feed:
    st.subheader("Live Wazuh feed")
    st.caption(
        "Continuously polls the local Wazuh indexer and runs every new alert through "
        "the guardrailed pipeline automatically — no manual fetch needed. Requires the "
        "Wazuh Docker stack to be running (see docs/ROADMAP_PLAN.md §10a)."
    )

    ctrl1, ctrl2, ctrl3 = st.columns([1, 2, 1])
    with ctrl1:
        live_on = st.toggle("Live feed active", value=False, key="live_feed_active")
    with ctrl2:
        poll_interval = st.slider("Poll interval (seconds)", 5, 60, 10, key="live_feed_interval")
    with ctrl3:
        if st.button("Clear feed", use_container_width=True):
            st.session_state["live_feed_items"] = []
            st.session_state["live_feed_seen"] = set()

    st.session_state.setdefault("live_feed_items", [])
    st.session_state.setdefault("live_feed_seen", set())

    from requests.exceptions import RequestException
    from experiments.evaluation.wazuh_integration_test import (
        dedupe_alerts, fetch_recent_alerts, wazuh_alert_to_security_alert,
    )

    @st.fragment(run_every=f"{poll_interval}s" if live_on else None)
    def _live_feed_poll():
        if live_on:
            try:
                docs = dedupe_alerts(fetch_recent_alerts())
                new_count = 0
                for doc in docs:
                    src = doc["_source"]
                    # Same dedupe key as wazuh_integration_test.py: Wazuh's SCA
                    # module re-runs its full checklist on every scan and reindexes
                    # identical content under a new _id, so keying on rule.id +
                    # full_log (not _id) is what actually stops repeated LLM calls
                    # on the same unchanged alert across polls.
                    key = (src.get("rule", {}).get("id"), src.get("full_log"))
                    if key in st.session_state["live_feed_seen"]:
                        continue
                    st.session_state["live_feed_seen"].add(key)

                    alert = wazuh_alert_to_security_alert(doc)
                    # The LLM call (Groq) can fail independently of the Wazuh
                    # connection -- e.g. daily token quota exhausted. That
                    # shouldn't crash the whole live-feed fragment or stop
                    # later alerts/polls from being tried; record it as a
                    # failed row instead and keep going.
                    try:
                        report = analyse_alert(alert)
                        row = {
                            "fetched_at": time.strftime("%H:%M:%S"),
                            "alert_id": alert.alert_id,
                            "rule_id": src.get("rule", {}).get("id"),
                            "rule_level": src.get("rule", {}).get("level"),
                            "severity_assessment": report.get("severity_assessment"),
                            "guardrail_blocked": report.get("guardrail_blocked", False),
                            "requires_review": report.get("requires_review", False),
                            "hallucinated_cves": report.get("hallucinated_cves", []),
                            "hallucinated_attack_techniques": report.get("hallucinated_attack_techniques", []),
                            "threat_summary": report.get("threat_summary"),
                        }
                    except Exception as e:
                        row = {
                            "fetched_at": time.strftime("%H:%M:%S"),
                            "alert_id": alert.alert_id,
                            "rule_id": src.get("rule", {}).get("id"),
                            "rule_level": src.get("rule", {}).get("level"),
                            "severity_assessment": "ERROR",
                            "guardrail_blocked": None,
                            "requires_review": None,
                            "hallucinated_cves": [],
                            "hallucinated_attack_techniques": [],
                            "threat_summary": f"LLM call failed: {e}",
                        }
                    st.session_state["live_feed_items"].insert(0, row)
                    new_count += 1
                st.session_state["live_feed_items"] = st.session_state["live_feed_items"][:100]
                st.caption(
                    f"Live — last polled {time.strftime('%H:%M:%S')}, next in {poll_interval}s — "
                    f"{new_count} new alert(s) this poll, {len(st.session_state['live_feed_items'])} total"
                )
            except RequestException as e:
                st.error(f"Could not reach the Wazuh indexer — is the Docker stack running? ({e})")
        else:
            st.caption("Paused — toggle 'Live feed active' above to start polling.")

        items = st.session_state["live_feed_items"]
        if items:
            st.dataframe(pd.DataFrame(items), hide_index=True, use_container_width=True)
        else:
            st.info("No alerts seen yet.")

    _live_feed_poll()


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

    def flatten_report_rows(rows, meta_keys):
        """soc_integration/wazuh_integration results nest the guardrail
        report under 'report' alongside per-row metadata (e.g. rule_id) --
        unlike the bait tests, which store the report flat. Flatten for
        table display.
        """
        flat_rows = []
        for row in rows:
            flat = {k: row.get(k) for k in meta_keys}
            flat.update(row.get("report", {}))
            flat_rows.append(flat)
        return flat_rows

    guardrail_results = load_json("guardrail_results.json")
    cicids_results = load_json("cicids2017_results.json")
    fp_results = load_json("fp_rate_results.json")
    threading_results = load_json("threading_benchmark_results.json")
    mp_results = load_json("multiprocessing_benchmark_results.json")
    cve_bait_results = load_json("cve_bait_results.json")
    attack_bait_results = load_json("attack_bait_results.json")
    pii_bait_results = load_json("pii_bait_results.json")
    selfcheckgpt_results = load_json("selfcheckgpt_results.json")
    soc_integration_results = load_json("soc_integration_results.json")
    soc_cve_pool_results = load_json("soc_integration_cve_pool_results.json")
    wazuh_results = load_json("wazuh_integration_results.json")

    # Added for the paper's central finding + supporting-evaluation sections
    # (previously computed/reported but never wired into this dashboard).
    mcnemar_gpt = load_json("selfcheckgpt_vs_deterministic_mcnemar.json")
    mcnemar_qwen = load_json("selfcheckgpt_vs_deterministic_mcnemar_qwen_qwen3_6_27b.json")
    selfcheckgpt_qwen_results = load_json("selfcheckgpt_results_qwen_qwen3_6_27b.json")
    grounding_summary = load_json("grounding_benchmark_summary.json")
    llm_judge_same = load_json("llm_judge_synthetic_results.json")
    llm_judge_qwen = load_json("llm_judge_synthetic_results_qwen_qwen3_6_27b.json")
    guardrail_comparison = load_json("guardrail_comparison.json")
    guardrail_comparison_sig = load_json("guardrail_comparison_significance.json")
    fresh_process_results = load_json("fresh_process_benchmark_results.json")
    relevance_classifier_results = None
    _rc_path = "experiments/evaluation/relevance_classifier_validation/relevance_classifier_validation_results.json"
    if os.path.exists(_rc_path):
        with open(_rc_path) as f:
            relevance_classifier_results = json.load(f)

    st.header("Central finding: SelfCheckGPT vs. deterministic grounding")
    st.caption(
        "The paper's one statistically-confirmed result: does the deterministic "
        "grounding checker catch citations that a self-consistency-only signal "
        "(SelfCheckGPT — same claim, resampled 3x, flagged unstable if it "
        "disagrees with itself) misses? Tested on the identical 60-alert CVE "
        "pool, on two independent model families, so this isn't a one-model "
        "artifact."
    )

    fig1_path = "docs/paper/figures/fig_selfcheckgpt_by_class.png"
    if os.path.exists(fig1_path):
        st.image(fig1_path, use_container_width=False, width=650)

    mc1, mc2 = st.columns(2)
    with mc1:
        st.markdown("**`openai/gpt-oss-20b` (report-generation model)**")
        if mcnemar_gpt is not None:
            ct = mcnemar_gpt["contingency"]
            st.dataframe(
                pd.DataFrame([ct]).T.rename(columns={0: "count"}),
                use_container_width=True,
            )
            sig = "significant" if mcnemar_gpt["significant_at_0.05"] else "not significant"
            st.metric("McNemar p-value", f"{mcnemar_gpt['p_value']:.4f}", f"{sig} at α=0.05")
        else:
            st.info("Run: python -m experiments.evaluation.selfcheckgpt_significance_test")
    with mc2:
        st.markdown("**`qwen/qwen3.6-27b` (cross-family replication)**")
        if mcnemar_qwen is not None:
            ct = mcnemar_qwen["contingency"]
            st.dataframe(
                pd.DataFrame([ct]).T.rename(columns={0: "count"}),
                use_container_width=True,
            )
            sig = "significant" if mcnemar_qwen["significant_at_0.05"] else "not significant"
            st.metric("McNemar p-value", f"{mcnemar_qwen['p_value']:.2e}", f"{sig} at α=0.05")
            st.caption(
                "SelfCheckGPT-only-correct = 0 — it never once beat the "
                "deterministic checker on a qwen-generated report."
            )
        else:
            st.info(
                "Run: GENERATOR_MODEL=qwen/qwen3.6-27b python -m "
                "experiments.evaluation.selfcheckgpt_significance_test"
            )

    if selfcheckgpt_qwen_results is not None and selfcheckgpt_qwen_results.get("run_complete"):
        st.caption(
            f"qwen SelfCheckGPT baseline: recall {selfcheckgpt_qwen_results['recall']:.1%} "
            f"(vs. {selfcheckgpt_results['recall']:.1%} for gpt-oss-20b, if available above) — "
            f"qwen recalls a withheld-but-correct CVE *more* consistently across resamples, "
            f"so the self-consistency blind spot is stronger, not weaker, on the second model."
        )

    st.divider()

    st.subheader("Cross-source grounding summary")
    st.caption(
        "Pools every already-run grounding source (bait tests + real/third-party data) "
        "into one view — no new alerts or LLM calls, pure aggregation."
    )
    if grounding_summary is not None:
        pooled = grounding_summary["pooled"]
        gs1, gs2, gs3 = st.columns(3)
        gs1.metric(
            "CVE-checker sources (pooled)",
            f"{pooled['cve_sources_pooled_ungrounded_count']}/{pooled['cve_sources_pooled_n']}",
            f"{pooled['cve_sources_pooled_ungrounded_rate']:.2%}",
        )
        gs2.metric(
            "ATT&CK-checker sources (pooled)",
            f"{pooled['attack_sources_pooled_ungrounded_count']}/{pooled['attack_sources_pooled_n']}",
            f"{pooled['attack_sources_pooled_ungrounded_rate']:.2%}",
        )
        gs3.metric("Total alerts pooled", pooled["total_alerts_across_all_sources"])
        st.dataframe(pd.DataFrame(grounding_summary["sources"]), hide_index=True, use_container_width=True)
    else:
        st.info("Run: python -m experiments.evaluation.grounding_benchmark_summary")

    st.divider()

    st.subheader("Summary")

    c1, c2, c3, c4, c5, c6, c7, c8 = st.columns(8)

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

    if attack_bait_results is not None:
        _attack_overall = attack_bait_results["overall"]
        c6.metric("ATT&CK citations requiring review", f"{_attack_overall['requires_review_rate']:.1%}",
                   f"{_attack_overall['ungrounded_count']}/{_attack_overall['n']} ungrounded citation(s)")
    else:
        c6.metric("ATT&CK hallucination rate", "—")

    if pii_bait_results is not None:
        c7.metric("PII redaction rate (bait alerts)",
                   f"{pii_bait_results['pii_alerts_detection_rate']:.1%}" if pii_bait_results['pii_alerts_detection_rate'] is not None else "—",
                   f"{pii_bait_results['clean_alerts_false_positives']} false positive(s) on clean alerts")
    else:
        c7.metric("PII redaction rate", "—")

    if selfcheckgpt_results is not None and selfcheckgpt_results.get("run_complete"):
        cm = selfcheckgpt_results["confusion_matrix"]
        c8.metric("SelfCheckGPT recall", f"{selfcheckgpt_results['recall']:.1%}",
                   f"precision {selfcheckgpt_results['precision']:.1%} — "
                   f"{len(selfcheckgpt_results.get('stable_but_wrong_alert_ids', []))} stable-but-ungrounded")
    else:
        c8.metric("SelfCheckGPT recall", "—")

    st.markdown("**Independent alert sources** (not hand-authored — rule-engine-generated or live-observed)")
    d1, d2, d3 = st.columns(3)

    if soc_integration_results is not None:
        d1.metric("Secure_SOC_AI incidents tested", soc_integration_results["total_tested"],
                   f"{soc_integration_results['requires_review_count']} requiring review")
    else:
        d1.metric("Secure_SOC_AI incidents tested", "—")

    if soc_cve_pool_results is not None:
        s = soc_cve_pool_results["summary"]
        d2.metric("CVE pool: correct citation when told", f"{s['stated']['cited_ground_truth_cve_rate']:.0%}",
                   f"vs {s['bait']['cited_ground_truth_cve_rate']:.0%} when not told")
    else:
        d2.metric("CVE pool: correct citation when told", "—")

    if wazuh_results is not None:
        d3.metric("Wazuh live alerts tested", wazuh_results["total_tested"],
                   f"{wazuh_results['requires_review_count']} requiring review")
    else:
        d3.metric("Wazuh live alerts tested", "—")

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

    st.subheader("Output guardrail — MITRE ATT&CK hallucination test")
    if attack_bait_results is not None:
        st.dataframe(
            pd.DataFrame(attack_bait_results["results"])[
                ["alert_id", "severity_assessment", "threat_type", "hallucinated_attack_techniques", "requires_review"]
            ],
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.info("No ATT&CK-bait results found yet — run: python -m experiments.evaluation.attack_bait_test")

    st.divider()

    st.subheader("Output guardrail — PII redaction test")
    st.caption(
        "Presidio-based redaction (Threat T3, docs/proposal.md) over the generated report's "
        "own text — different question from the CVE/ATT&CK checks above: not 'did the model "
        "hallucinate a claim', but 'did sensitive data present in the raw alert survive "
        "unredacted into the report'. See docs/ROADMAP_PLAN.md §5."
    )
    if pii_bait_results is not None:
        st.dataframe(
            pd.DataFrame(pii_bait_results["results"])[
                ["alert_id", "kind", "expected_entities", "detected_entities", "pii_found", "residual_pii"]
            ],
            hide_index=True,
            use_container_width=True,
        )
        if pii_bait_results["residual_pii_after_redaction_count"] > 0:
            st.warning(f"{pii_bait_results['residual_pii_after_redaction_count']} alert(s) had PII survive "
                       f"redaction — see 'residual_pii' column.")
    else:
        st.info("No PII-bait results found yet — run: python -m experiments.evaluation.pii_bait_test")

    st.markdown("**Same guardrail, on real Wazuh alert text**")
    st.caption(
        "The bait test above uses hand-authored alerts built specifically to test PII "
        "detection. This is the same guardrail's output on real Wazuh live-agent alert "
        "text instead — surfaces false positives the narrow bait test never contained "
        "(e.g. URL paths or command strings misread as a person's name)."
    )
    if wazuh_results is not None:
        wazuh_pii_df = pd.DataFrame(flatten_report_rows(
            wazuh_results["results"], ["wazuh_alert_id", "rule_id"],
        ))
        wazuh_pii_df["pii_found"] = wazuh_pii_df["pii_detections"].apply(lambda d: len(d) > 0)
        wazuh_pii_df["pii_detections_summary"] = wazuh_pii_df["pii_detections"].apply(
            lambda d: "; ".join(f"{e['entity_type']}: \"{e['text']}\" ({e['score']})" for e in d)
        )
        st.dataframe(
            wazuh_pii_df[["wazuh_alert_id", "rule_id", "severity_assessment",
                          "pii_found", "pii_detections_summary", "requires_review"]].rename(
                columns={"pii_detections_summary": "pii_detections"}
            ),
            hide_index=True,
            use_container_width=True,
        )
        n_pii_flagged = int(wazuh_pii_df["pii_found"].sum())
        if n_pii_flagged > 0:
            st.warning(f"{n_pii_flagged} live Wazuh alert(s) had a PII detection — see 'pii_detections' "
                       f"column to check whether each is a real leak or a false positive.")
    else:
        st.info("No Wazuh results found yet — run: python -m experiments.evaluation.wazuh_integration_test "
                "(requires the local Wazuh Docker stack to be running)")

    st.divider()

    st.subheader("SelfCheckGPT baseline — self-consistency vs. external grounding")
    st.caption(
        "A different question again: not 'is this citation grounded in the evidence', but "
        "'does the model keep making the same claim when resampled'. `expected_ungrounded` is "
        "the alert's true construction (CVE withheld = should be flagged); `flagged_unstable` is "
        "what SelfCheckGPT actually predicted. Watch for rows where `expected_ungrounded` is True, "
        "`flagged_unstable` is False, and `majority_id` equals `ground_truth_cve` — SelfCheckGPT's "
        "blind spot: the model consistently recalled the *correct* withheld CVE from training "
        "knowledge, so nothing looked unstable, even though the checker still (correctly) flags it "
        "as ungrounded. See docs/paper/paper_draft.md Sect. 4.9."
    )
    if selfcheckgpt_results is not None:
        st.dataframe(
            pd.DataFrame(selfcheckgpt_results["results"])[
                ["alert_id", "class", "expected_ungrounded", "flagged_unstable",
                 "majority_id", "ground_truth_cve", "agreement_rate"]
            ],
            hide_index=True,
            use_container_width=True,
        )
        if not selfcheckgpt_results.get("run_complete"):
            st.info(f"Run in progress: {selfcheckgpt_results.get('n_alerts_completed', 0)}/"
                    f"{selfcheckgpt_results.get('n_alerts_total', '?')} alerts completed so far.")
    else:
        st.info("No SelfCheckGPT results found yet — run: python -m experiments.evaluation.selfcheckgpt_test")

    st.divider()

    st.subheader("Secure_SOC_AI integration — rule-engine-generated incidents")
    st.caption(
        "Incidents from Secure_SOC_AI's own detection + correlation layer (76 incidents, "
        "7 rule types), not hand-authored — tests the pipeline against realistic, "
        "non-adversarial alerts. See docs/INTEGRATION_PLAN.md."
    )
    if soc_integration_results is not None:
        st.dataframe(
            pd.DataFrame(flatten_report_rows(
                soc_integration_results["results"],
                ["incident_id", "entity", "rule_ids", "ground_truth_mitre"],
            ))[["incident_id", "entity", "rule_ids", "severity_assessment",
                "hallucinated_attack_techniques", "hallucinated_cves", "requires_review"]],
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.info("No results found yet — run: python -m experiments.evaluation.soc_integration_test")

    st.divider()

    st.subheader("CVE pool — 15 real CVEs, bait vs. stated citation style")
    st.caption(
        "Complements the CVE-bait test above at larger scale (60 alerts, 15 real NVD-listed "
        "CVEs). 'Bait' withholds the CVE number to test spontaneous citation; 'stated' gives "
        "it directly to test correct reflection. See docs/ROADMAP_PLAN.md §5."
    )
    if soc_cve_pool_results is not None:
        st.dataframe(
            pd.DataFrame(flatten_report_rows(
                soc_cve_pool_results["results"],
                ["ground_truth_cve", "cve_name", "style"],
            ))[["ground_truth_cve", "cve_name", "style", "severity_assessment",
                "hallucinated_cves", "requires_review"]],
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.info("No results found yet — run: python -m experiments.evaluation.soc_integration_cve_pool_test")

    st.divider()

    st.subheader("Wazuh integration — live agent alerts")
    st.caption(
        "Real alerts observed from a running Wazuh agent (Docker, local-only), not "
        "synthetic or hand-authored — includes a real SSH brute-force attempt Wazuh's own "
        "correlation logic flagged on its own. See docs/ROADMAP_PLAN.md §10a."
    )
    if wazuh_results is not None:
        st.dataframe(
            pd.DataFrame(flatten_report_rows(
                wazuh_results["results"],
                ["wazuh_alert_id", "rule_id", "rule_level"],
            ))[["rule_id", "rule_level", "severity_assessment",
                "hallucinated_attack_techniques", "hallucinated_cves", "requires_review"]],
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.info("No results found yet — run: python -m experiments.evaluation.wazuh_integration_test "
                "(requires the local Wazuh Docker stack to be running)")

    st.divider()

    st.header("Supporting evaluation")
    st.caption(
        "Validates the pipeline's other layers and an alternative verification "
        "strategy — none of these carry equal weight to the central finding above, "
        "reported here for completeness."
    )

    st.subheader("LLM-judge baseline (alternative verification strategy)")
    st.caption(
        "Instead of a deterministic checker, ask an LLM to directly judge whether "
        "a citation is grounded. Tested with two judges: the same model that "
        "generates reports (same-family) and a genuinely different, "
        "independently-hosted model (cross-family) — rules out the judge simply "
        "favoring its own model family's output."
    )
    lj1, lj2 = st.columns(2)
    with lj1:
        st.markdown("**Same-family judge (`openai/gpt-oss-20b`)**")
        if llm_judge_same is not None:
            o = llm_judge_same["overall"]
            st.metric(
                f"Accuracy (n={llm_judge_same['n_completed']}/{llm_judge_same['n_samples']})",
                f"{o['accuracy']:.1%}",
                f"precision {o['precision']:.1%} / recall {o['recall']:.1%}",
            )
        else:
            st.info("Run: python -m experiments.evaluation.llm_judge_synthetic_test")
    with lj2:
        st.markdown("**Cross-family judge (`qwen/qwen3.6-27b`)**")
        if llm_judge_qwen is not None:
            o = llm_judge_qwen["overall"]
            complete = "complete" if llm_judge_qwen.get("run_complete") else "in progress"
            st.metric(
                f"Accuracy (n={llm_judge_qwen['n_completed']}/{llm_judge_qwen['n_samples']}, {complete})",
                f"{o['accuracy']:.1%}",
                f"precision {o['precision']:.1%} / recall {o['recall']:.1%}",
            )
        else:
            st.info(
                "Run: LLM_JUDGE_MODEL=qwen/qwen3.6-27b python -m "
                "experiments.evaluation.llm_judge_synthetic_test"
            )

    st.divider()

    st.subheader("Relevance classifier validation")
    st.caption(
        "The REAL_AND_PLAUSIBLE/REAL_BUT_IRRELEVANT split rests on a topical-overlap "
        "score — validated here against independent human judgment (80 labeled "
        "alert/CVE pairs) rather than left as an unchecked heuristic."
    )
    if relevance_classifier_results is not None:
        r = relevance_classifier_results
        rc1, rc2, rc3, rc4 = st.columns(4)
        rc1.metric("Accuracy", f"{r['accuracy']:.1%}", f"n={r['n_labeled']}")
        rc2.metric("Precision", f"{r['precision']:.1%}")
        rc3.metric("Recall", f"{r['recall']:.1%}")
        rc4.metric("F1", f"{r['f1']:.1%}")
        cm = r["confusion_matrix"]
        st.caption(f"TP={cm['tp']}, FP={cm['fp']}, TN={cm['tn']}, FN={cm['fn']} — all 6 disagreements "
                   f"cluster at the 0.15 decision threshold, a boundary-case failure mode not general unreliability.")
    else:
        st.info("Run: experiments/evaluation/relevance_classifier_validation/score_labels.py")

    st.divider()

    st.subheader("Input guardrail comparison")
    st.caption(
        "Our hybrid (deterministic pattern list + Pytector fallback) vs. two "
        "maintained open-source alternatives, on a 119-sample held-out set."
    )
    if guardrail_comparison is not None:
        impl_rows = []
        for name, impl in guardrail_comparison["implementations"].items():
            impl_rows.append({
                "implementation": name,
                "precision": impl["precision"],
                "recall": impl["recall"],
                "f1": impl["f1"],
                "false_positives": impl["confusion_matrix"]["fp"],
                "median_latency_ms": impl.get("median_latency_ms"),
            })
        st.dataframe(pd.DataFrame(impl_rows), hide_index=True, use_container_width=True)
    else:
        st.info("Run: python -m experiments.evaluation.guardrail_comparison.run_comparison")

    if guardrail_comparison_sig is not None:
        st.markdown("**McNemar significance, raw vs. Holm-Bonferroni corrected "
                     f"(family size {guardrail_comparison_sig['comparisons'].__len__()})**")
        sig_rows = []
        for c in guardrail_comparison_sig["comparisons"]:
            sig_rows.append({
                "comparison": f"{c['a']} vs. {c['b']}",
                "raw_p": round(c["p_value"], 4),
                "sig_raw": c["significant_at_0.05"],
                "holm_bonferroni_p": round(c["p_value_holm_bonferroni"], 4),
                "sig_corrected": c["significant_at_0.05_holm_bonferroni"],
            })
        st.dataframe(pd.DataFrame(sig_rows), hide_index=True, use_container_width=True)
        st.caption(
            "Only baseline-vs-hybrid survives correction — the other raw-significant "
            "results sat close to the α=0.05 line and don't survive being tested as a family."
        )
    else:
        st.info("Run: python -m experiments.evaluation.guardrail_comparison.significance_test")

    st.divider()

    st.subheader("Concurrency benchmark (fresh-process repeats, redone)")
    st.caption(
        "Redone with each repeat as a genuinely independent subprocess (not looped "
        "in one long-running process) plus a mocked-LLM variant to separate guardrail "
        "overhead from live Groq network variance. Found and fixed a real unlocked "
        "race condition in the pytector model loader along the way."
    )
    fig2_path = "docs/paper/figures/fig_concurrency_throughput.png"
    if os.path.exists(fig2_path):
        st.image(fig2_path, use_container_width=True)
    if fresh_process_results is not None:
        with st.expander("Raw fresh-process benchmark tables"):
            for key, rows in fresh_process_results.items():
                st.markdown(f"**{key}**")
                st.dataframe(pd.DataFrame(flatten_benchmark_rows(rows)), hide_index=True, use_container_width=True)
    else:
        st.info("Run: python -m experiments.evaluation.fresh_process_benchmark")

    st.divider()

    st.subheader("Alert results")
    view_choice = st.radio(
        "Source",
        ["Synthetic (week 4)", "CICIDS2017 (real)", "False positive test", "CVE bait test", "ATT&CK bait test",
         "PII bait test", "SelfCheckGPT comparison", "Secure_SOC_AI incidents", "CVE pool", "Wazuh (live)"],
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
    elif view_choice == "ATT&CK bait test" and attack_bait_results is not None:
        st.dataframe(pd.DataFrame(attack_bait_results["results"]), hide_index=True, use_container_width=True)
    elif view_choice == "PII bait test" and pii_bait_results is not None:
        st.dataframe(pd.DataFrame(pii_bait_results["results"]), hide_index=True, use_container_width=True)
    elif view_choice == "SelfCheckGPT comparison" and selfcheckgpt_results is not None:
        st.dataframe(pd.DataFrame(selfcheckgpt_results["results"]), hide_index=True, use_container_width=True)
    elif view_choice == "Secure_SOC_AI incidents" and soc_integration_results is not None:
        st.dataframe(pd.DataFrame(flatten_report_rows(
            soc_integration_results["results"], ["incident_id", "entity", "rule_ids", "ground_truth_mitre"],
        )), hide_index=True, use_container_width=True)
    elif view_choice == "CVE pool" and soc_cve_pool_results is not None:
        st.dataframe(pd.DataFrame(flatten_report_rows(
            soc_cve_pool_results["results"], ["ground_truth_cve", "cve_name", "style"],
        )), hide_index=True, use_container_width=True)
    elif view_choice == "Wazuh (live)" and wazuh_results is not None:
        st.dataframe(pd.DataFrame(flatten_report_rows(
            wazuh_results["results"], ["wazuh_alert_id", "rule_id", "rule_level"],
        )), hide_index=True, use_container_width=True)
    else:
        st.info("No saved results found for this source yet — run the corresponding script first.")
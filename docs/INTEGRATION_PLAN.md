# Integration Plan: Secure_SOC_AI as an external alert source

Source repo: https://github.com/engranaabubakar/Secure_SOC_AI (MIT license)

## 1. Goal

Test this project's guardrail pipeline (`src/agent/soc_agent.py::analyse_alert`)
against realistic, non-hand-crafted incidents, instead of only our own small
(n=6) hand-authored CVE-bait / ATT&CK-bait alert sets.

Secure_SOC_AI is a third-party, open-source SOC engine: Wazuh-style detection
→ rule engine + behavioral anomaly detection → alert correlation into
incidents → LLM triage. We use its **alert generation** (detection +
correlation) as a source of realistic incidents, and run **our own**
guardrailed pipeline as the triage step instead of its built-in one.

Its own triage step (`triage/engine.py`, Groq/Claude/heuristic) and its own
basic injection defense (`triage/sanitize.py`, regex-only) are **not** used
anywhere in this integration — we only import its detection/correlation
layer, which is pure local Python with no network calls.

## 2. Decisions considered

### Decision 1 — how deep to integrate

| Option | What it means | Thesis value | Build effort | Data scale |
|---|---|---|---|---|
| **A. Post-hoc audit** | Run their full stack as-is (their own Groq/Claude triage), pull finished `Incident` objects via their REST API or SQLite store, run our CVE/ATT&CK grounding checker against their triage's output text only. | Weak — only tests whether our checker catches hallucinations in *someone else's* LLM output. Tangential to our own pipeline. | Looked lower-risk at first glance (just API/DB reads) but needs their Docker stack + a live Groq/Claude key running. | Worse — their own demo data collapses to only **3** incidents, fewer than our existing 6-alert bait sets. |
| **B. Replace their triage step** (chosen) | Use their local rule engine + correlator to generate incidents from an event stream, convert each `Incident` → our `SecurityAlert`, run through **our** `analyse_alert()` (our input guardrail + LLM + our output guardrail) instead of their triage engine. | Strong — directly tests our full guardrail pipeline against realistically-generated incidents, addressing the "our bait sets are small and self-authored" weakness. | Their detection/correlation modules are pure local Python (no Docker/Wazuh/API key needed for that part) — a schema-mapping function, not a service integration. | Better — their rule engine is free/local, so we can feed it a much larger synthetic event set than their 15-event demo and generate many more incidents. |

**Decision: B.** Better on all three axes once actually inspected — not just lower perceived effort.

### Decision 2 — where do the input events come from, without live Wazuh agents

Wazuh is optional in Secure_SOC_AI, not required. Its own 5-minute quick-start
demo doesn't use Wazuh either — it feeds events from a plain JSONL file
straight into the same local rule engine / anomaly detector that Wazuh-sourced
events would go through. We use the same path: no Wazuh, no live machines,
just a JSONL event file in their ECS-lite `Event` schema.

| Option | Pros | Cons |
|---|---|---|
| Use their bundled `sample_data/demo_events.jsonl` only | Zero authoring effort | Only 15 events → 3 incidents. Too small, same n-too-small problem we're trying to fix. |
| **Author our own larger synthetic JSONL** (chosen) | Full control over scenario diversity and count; deterministic/reproducible; can exercise all 7 vendored rules | Requires hand-writing realistic events per rule's match conditions |

**Decision:** author our own synthetic event set (see §4), larger and more diverse than their demo, covering all 7 of their shipped detection rules.

### Decision 3 — vendor their code, or depend on it live

| Option | Pros | Cons |
|---|---|---|
| `pip install git+https://github.com/engranaabubakar/Secure_SOC_AI.git` for the Python package (models/detect/correlate/ingest), **and** vendor a local copy of their 3 rule YAML files | Reproducible even if the external repo changes/disappears; rule files are tiny and MIT-licensed so redistribution is fine; avoids duplicating their detection/correlation logic in our own codebase | Adds one external pip dependency (installed with `--no-deps` since we already have pydantic/httpx etc.) |
| Fully vendor/copy their Python source too | No pip dependency at all | Duplicates and has to track upstream changes to real detection logic; more code to maintain for no real benefit |

**Decision:** pip-install the package (`--no-deps`, since `pydantic`/`httpx` etc. are already project dependencies), vendor only the rule YAML files.

### Decision 4 — does this violate the local-only constraint (issue #16)

No. Issue #16's local-only constraint applies to the **guardrail/detection
tooling being compared** ([[project_local_only_constraint]]), not to the SOC
agent's own LLM backend — Groq calls from our own `analyse_alert()` are
already an accepted exception. This integration doesn't call Secure_SOC_AI's
triage/LLM code at all; their rule engine and correlator are pure local
Python with no network calls. Our own grounding checks remain local
(NVD/MITRE-snapshot based) exactly as before.

## 3. Architecture

```
synthetic_events.jsonl (ours, authored)
        │
        ▼
secure_soc_ai.ingest.JsonlFileSource   → normalized Event objects
        │
        ▼
secure_soc_ai.detect.RuleEngine        ← vendored_rules/*.yml (from their repo)
  .evaluate(event)                       → Alert objects (each tagged with a
        │                                   ground-truth MITRE ATT&CK ID)
        ▼
secure_soc_ai.correlate.Correlator
  .process(alert)                      → Incident objects (deduped, grouped
        │                                   by entity within a time window)
        ▼
incident_to_security_alert()           ← OUR adapter function
        │                                 (maps Incident → SecurityAlert)
        ▼
src.agent.soc_agent.analyse_alert()    ← OUR guardrailed pipeline
  - check_injection (input guardrail)    (Secure_SOC_AI's own triage engine
  - Groq LLM call                         is never called)
  - CVE grounding check (output)
  - ATT&CK grounding check (output)
        │
        ▼
experiments/results/soc_integration_results.json
        │
        ▼
dashboard/app.py — new "SOC integration test" section
```

## 4. File paths (finalized)

| Path | Purpose | Status |
|---|---|---|
| `experiments/evaluation/soc_integration/vendored_rules/auth_bruteforce.yml` | Vendored copy of their brute-force/spray rules (AUTH-BRUTE-001, AUTH-SPRAY-001) | ✅ built |
| `experiments/evaluation/soc_integration/vendored_rules/network_exfil.yml` | Vendored copy of their network rules (NET-EXFIL-001, NET-C2-PORT-001, WEB-SQLI-001) | ✅ built |
| `experiments/evaluation/soc_integration/vendored_rules/suspicious_process.yml` | Vendored copy of their process rules (PROC-ENC-PS-001, PROC-LOLBIN-001) | ✅ built |
| `experiments/evaluation/soc_integration/synthetic_events.jsonl` | Our own authored event stream (~28 events), covering all 7 rules across 9 distinct entities/incidents: brute force, password spray, full multi-stage chain (encoded PowerShell → certutil LOLbin → C2 port → large exfil, all on one host), 2× SQL injection variants, standalone large exfil, standalone C2-port connection, 2× LOLbin variants (rundll32, mshta), plus a few benign filler events | ✅ built |
| `experiments/evaluation/soc_integration_test.py` | Adapter/runner script: ingest → detect → correlate → convert `Incident`→`SecurityAlert` → `analyse_alert()` → save results JSON, output shape modeled on `cve_bait_test.py`/`attack_bait_test.py` | ✅ built (not yet run) |
| `experiments/results/soc_integration_results.json` | Output of running the script — per-incident guardrail reports plus summary rates (ATT&CK ungrounded rate, CVE ungrounded rate, requires-review rate, injection-blocked count) | ❌ not yet generated |
| `dashboard/app.py` | New "SOC integration test" section, same pattern as the existing CVE-bait/ATT&CK-bait sections | ❌ not yet added |
| `requirements.txt` | Optionally add `secure-soc-ai @ git+https://github.com/engranaabubakar/Secure_SOC_AI.git` so the script is reproducible for others without a manual pip install | ❌ not yet added |

External dependency installed in the current environment: `secure-soc-ai` (pip, `--no-deps`, from GitHub) — not yet pinned in `requirements.txt`.

## 5. Step-by-step implementation phases

1. **Install & vendor** (done)
   - `pip install git+https://github.com/engranaabubakar/Secure_SOC_AI.git --no-deps`
   - Copy `rules/auth_bruteforce.yml`, `rules/network_exfil.yml`, `rules/suspicious_process.yml` into `experiments/evaluation/soc_integration/vendored_rules/`

2. **Author the synthetic event set** (done)
   - `experiments/evaluation/soc_integration/synthetic_events.jsonl`, hand-written to deterministically trigger all 7 vendored rules across 9 distinct entities/incidents

3. **Write the adapter/runner script** (done, not yet executed)
   - `experiments/evaluation/soc_integration_test.py`:
     - `incident_to_security_alert(incident)` — maps entity prefix (`src_ip:`/`host:`/`user:`) onto `SecurityAlert.source_ip`/`hostname`/`user`; builds `description` from incident title + rule names + tagged MITRE IDs (kept visible, not withheld — this is a realistic-alert test, not an adversarial bait test); pulls `destination_ip`/`port` from the first event that has them; joins up to 5 event command-lines/messages into `payload_snippet`
     - `run()` — reads events via `JsonlFileSource`, evaluates via `RuleEngine`, correlates via `Correlator` (calling `flush_stale()` at the end to capture any still-open incidents), runs each resulting incident through `analyse_alert()`, records ground-truth MITRE IDs per incident alongside the guardrail report, prints per-incident progress, computes summary rates, saves JSON to `experiments/results/soc_integration_results.json`

4. **Run it for real** *(not yet done — paused here per user instruction)*
   - `python -m experiments.evaluation.soc_integration_test`
   - Sanity-check the 9 expected incidents appear with the expected rule IDs
   - Spot-check a couple of `report`s manually before trusting the summary numbers

5. **Add dependency pin**
   - Add `secure-soc-ai @ git+https://github.com/engranaabubakar/Secure_SOC_AI.git` to `requirements.txt` so the script is reproducible from a clean install

6. **Wire into the dashboard**
   - New `st.subheader("SOC integration test — Secure_SOC_AI incidents")` section in `dashboard/app.py`, following the existing CVE-bait/ATT&CK-bait section pattern: load `soc_integration_results.json`, show summary metrics, show a `st.dataframe` of per-incident results (entity, rule_ids, ground_truth_mitre, severity_assessment, hallucinated_attack_techniques, requires_review)
   - Add `"SOC integration test"` to the `view_choice` radio options

7. **(Optional, later)** consider whether to also compute LLM precision/recall against `ground_truth_mitre` (i.e., not just "did it hallucinate an extra ID" but "did it correctly re-cite the real one") — this data is already captured per-result, so it's a follow-up analysis rather than new plumbing

## 6. Current state (as of this plan being written)

- ✅ `secure-soc-ai` package installed locally (not yet pinned in `requirements.txt`)
- ✅ Vendored rule files written (3 files)
- ✅ Synthetic event set written (1 file, ~28 events)
- ✅ Adapter/runner script written (`soc_integration_test.py`)
- ❌ Script has **not been run** — no results JSON exists yet
- ❌ Dashboard section **not added**
- ❌ Nothing has been committed to git — all of the above are untracked/new files only

Paused at this point per explicit instruction ("no dont write it") before running the script or touching the dashboard. Next action requires explicit go-ahead: run the script, review real output, then decide on the dashboard section and commit.

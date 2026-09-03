# E2 · Week-13 Regression Suite Green + Schema-Parity Integration Test
- **Labels:** engineering, priority:P0
- **Milestone:** M1 — Freeze Desk-Reject Risks
- **Acceptance items:** 7

---

## Summary
The paper's §4.1 says (paraphrased): *"the test suite stands at 145 passing tests with 1 failing NeMo historical fixture."* Two things are missing:
1. Week‑13 added 4 new `analyse_alert()` signature toggles (input/cve/attack/pii boolean args). The existing suite tests the individual stages but **zero tests verify the full end-to-end pipeline with toggle combinations**. External review §30 flags this explicitly.
2. The 1 failing test (abandoned NeMo baseline fixture) should not be visible in a journal-submission-ready green suite. It should be marked skipped with an explanation.

---

## Task 1 — Skip the Abandoned NeMo Fixture
Find the one failing NeMo test (grep repo for NeMo-related pytest files; usually in an early-week legacy file or week-10 tests):

```python
# Original test will look like:
@pytest.mark.asyncio
async def test_nemo_guardrail_legacy_thing():
    ...
```

Change it to:
```python
@pytest.mark.skip(reason="Abandoned NeMo baseline; NeMo guardrails are not in the production pipeline. See do-not-build list DN9.")
def test_nemo_guardrail_legacy_thing():
    pass
```

(Make sure it's `def` not `async def` + `pytest.mark.skip` so it doesn't try to import the asyncio runner needlessly.)

Run:
```bash
pytest tests/ -v --tb=short | tee tests/last_run.log
grep -E 'passed|failed|error|skipped' tests/last_run.log | tail -n 5
```

Expected output after the fix: `145 passed, 1 skipped` (NOT `145 passed, 1 failed`). If extra skips are fine but do NOT add skips for tests that actually exercise production code — skip only NeMo/historical abandoned fixtures.

- [ ] **AC1:** `pytest` run completes 145 passed, 1 skipped, 0 failed. No errors.
- [ ] **AC2:** `tests/last_run.log` committed (tee'd output, full log, not just summary). Supervisor can grep for test names.

---

## Task 2 — Schema-Parity Integration Test for 6 Ablation Toggle Configs
Create **NEW file**: `tests/test_soc_agent_schema_parity.py`

This test must run **end-to-end with a MOCKED LLM**, not the real Groq API. It must pass offline in 0.1 seconds (no API calls, no quota). This is the single most important test a reviewer can run.

### Test structure

**Step 1.** Write a minimal `MockChatGroq` class that returns a fixed SOC report JSON for any input. This is not a "unit test of correctness" — it's a schema-parity test: every toggle config must produce a JSON with the EXACT same top-level keys and typed fields (ints are int, lists are lists, bools are bool), even when guardrails are disabled.

**Step 2.** Create 2 alert fixtures: ALERT-001 (SSH brute) and ALERT-003 (port scan) from [alert_schema.py](file:///d:/NUST/ONT/SIP-2026/CNIT/13-secureagent-soc-gaurdrails/src/agent/alert_schema.py).

**Step 3.** For every one of the 6 ablation configs (Full / -I / -C / -A / -P / None — see R3 config-table for toggle boolean tuple):
```python
CONFIGS = [
    ("C0_FULL", dict(input=True, cve=True, attack=True, pii=True)),
    ("C1_NO_INPUT", dict(input=False, cve=True, attack=True, pii=True)),
    ("C2_NO_CVE", dict(input=True, cve=False, attack=True, pii=True)),
    ("C3_NO_ATTACK", dict(input=True, cve=True, attack=False, pii=True)),
    ("C4_NO_PII", dict(input=True, cve=True, attack=True, pii=False)),
    ("C5_NONE", dict(input=False, cve=False, attack=False, pii=False)),
]
```

Call `analyse_alert(alert, input_guardrail_enabled=cfg['input'], cve_guardrail_enabled=cfg['cve'], attack_guardrail_enabled=cfg['attack'], pii_guardrail_enabled=cfg['pii'])` for all 12 (6 configs × 2 alerts) combinations.

**Step 4.** Assertions per result:
- All 12 result-dicts have **exactly the same set of top-level keys**. No key is missing in any config.
- Key types are consistent: `severity_score ∈ [0.0,1.0]` (float, never None), `requires_review ∈ {True, False}` (bool, never None), `citations_detected` is a list (possibly empty, never None), `pii_redacted_count ∈ ℕ∪{0}` (int, never None), etc. — at minimum, assert all keys from alert_schema output fields are present and non-None.
- For disabled stages that return "nothing-found" sentinel: assert that the sentinel string/structure is present for that config's disabled stage, not `None`.
- `time_per_stage_ms` dict (if present in schema) has 4 keys for input/cve/attack/pii even if value is 0.0 when disabled.

### Mocking strategy
Use `unittest.mock.patch` to replace `langchain_groq.ChatGroq` with a MockChatGroq that returns a hardcoded JSON response. Do NOT try to mock individual sub-functions of the pipeline; the whole point is that toggles + their "nothing-found" fallbacks populate the schema correctly through the real control flow, only the LLM call itself is replaced.

```python
# top of test_soc_agent_schema_parity.py
from unittest.mock import patch, MagicMock

SAMPLE_REPORT_TEXT = '''
{
  "severity_score": 0.62,
  "requires_review": false,
  "summary": "mocked for schema parity",
  "citations_detected": [],
  "attck_detected": [],
  "pii_redacted_count": 0,
  "evidence_pack": {"source_ips":[],"destination_ips":[],"users":[],"hostnames":[],"hashes":[],"ports":[],"text_snippet":""},
  "stages_ms": {"input":1,"cve":1,"attack":1,"pii":1}
}
'''

class MockChatGroq:
    def __init__(self, *a, **kw): pass
    def invoke(self, *a, **kw):
        m = MagicMock()
        m.content = SAMPLE_REPORT_TEXT
        return m

@patch('src.agent.soc_agent.ChatGroq', side_effect=MockChatGroq)
def test_schema_parity_all_configs(mock_chat_groq):
    ...
```

- [ ] **AC3:** `test_soc_agent_schema_parity.py` committed.
- [ ] **AC4:** Test runs with 0 network calls. Disconnect from internet / `export GROQ_API_KEY=definitely-wrong` → test still PASSES in < 30 seconds.
- [ ] **AC5:** All 12 (6 cfg × 2 alerts) output dictionaries have identical top-level key sets; zero non-None violations for required schema fields.

---

## Task 3 — Re-run Full Suite and Commit Fresh Log
After tests pass. Run once more to confirm everything is green:
```bash
pytest tests/ -v --tb=short --no-header | tee tests/last_run.log
```

Expected: `145 passed, 1 skipped, 0 failed`. (Or 145 + N schema-parity tests passed, if you split them into parametrized multiple tests. All green.)

Update `sn-article.tex` §4.1 "Test Suite Status" sentence with the actual final count. E.g.:
> *"The test suite on week-13 commit <short-SHA> reports 145 unit tests + 1 parametrized end-to-end schema-parity test passing, with 1 historical NeMo baseline fixture explicitly skipped (not used in the production pipeline)."*

- [ ] **AC6:** `tests/last_run.log` committed. Final pass count ≥ 145 all-green + 1 skipped only = NeMo abandoned.
- [ ] **AC7:** §4.1 "test suite currently stands at …" sentence in manuscript matches the logged count.

---
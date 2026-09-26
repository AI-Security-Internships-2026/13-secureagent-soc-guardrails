"""
experiments/evaluation/relevance_classifier_validation/build_attack_annotation_sheet.py

Issue #43 (R4), Part B, Task B.2 -- unlike the CVE side (Part A), the
ATT&CK relevance pairs (attack_pairs_to_label.csv, 103 pairs, built in
build_attack_pairs.py) have never been labeled by anyone at all: there
is no "annotator 1" pass to blind-check against yet. Per the same
degraded-scope decision as the CVE side (issue's own "Risks &
Mitigations": no second independent annotator recruited), this builds
the FULL blind annotation sheet -- all 103 pairs, single annotator -- to
establish the ATT&CK side's first real ground truth, rather than a
20%-of-an-existing-pass cross-check (there's no existing pass to check
against here).

Blinding: attack_pairs_to_label.csv's own `candidate_technique_description`
field is already prefixed with the technique's real name (e.g. "Golden
Ticket: Adversaries who..."), baked in when build_attack_pairs.py wrote
it. This strips that prefix back off, re-deriving the bare description
text directly from the same local MITRE snapshot the real guardrail
uses, and redacts the row's own technique ID (the T-number, the actual
look-up-able identifier -- the direct equivalent of hiding a CVE number)
if it leaks into the visible alert or description text.

The technique's plain-English NAME is deliberately left unredacted,
unlike an early draft of this script. Tried redacting it too, matching
the CVE side's ID-hiding as closely as possible -- but MITRE's official
descriptions routinely use a technique's own name as an ordinary
descriptive noun in their own prose (e.g. T1566 Phishing's description:
"Adversaries may send phishing messages..."), not as a rare
self-reference the way a CVE description occasionally cites its own
number. Redacting "Phishing" 10 times in one paragraph doesn't blind
anything meaningful -- the remaining sentence still obviously describes
phishing, so an annotator loses nothing by inferring it, and gains a
genuine reading-comprehension problem instead. The CVE-side redaction
never had this issue because NVD prose is number-based and doesn't use
colloquial nicknames in the description text -- there is no CVE
equivalent of "phishing" to trip over. Hiding the ID string is where the
real look-up shortcut lives (a technique's T-number is what an annotator
would need to search for its real name/fame), so that's what's redacted
here; the descriptive prose is left intact and readable.

Produces:
  attack_annotation_BLIND.xlsx      -- the 103-pair blind sheet to fill in.
  attack_annotation_key_HIDDEN.csv  -- pair_id, alert_id, candidate_technique_id
      for all 103 pairs (not for the labeler -- needed later to compute
      pipeline accuracy against the resolved human label).

Usage:
    python -m experiments.evaluation.relevance_classifier_validation.build_attack_annotation_sheet
"""

import csv
import os
import re

from openpyxl import Workbook
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.styles import Font, Alignment

from src.guardrails.attack_grounding import _load_attack_techniques

HERE = os.path.dirname(__file__)
SOURCE_PATH = os.path.join(HERE, "attack_pairs_to_label.csv")
BLIND_XLSX_PATH = os.path.join(HERE, "attack_annotation_BLIND.xlsx")
KEY_CSV_PATH = os.path.join(HERE, "attack_annotation_key_HIDDEN.csv")

INSTRUCTIONS = [
    ["Relevance annotation -- ATT&CK pairs, single annotator (issue #43/R4 Part B)"],
    [],
    ["For each row, read the alert evidence and the technique description, then decide:"],
    ["does the technique description plausibly explain/match what the alert evidence describes?"],
    [],
    ["Put exactly one of these two values in the 'your_label' column (a dropdown is provided):"],
    ["  relevant      -- the description is a plausible match for the alert's behavior"],
    ["  not_relevant  -- the description does not match what the alert describes"],
    [],
    ["Rules:"],
    ["  1. Work independently, in one or a few sittings -- try not to let earlier rows anchor later ones."],
    ["  2. Do not look up the technique online or try to identify its ATT&CK ID/name --"],
    ["     the identifier has been deliberately withheld so the label reflects the text alone,"],
    ["     not name recognition."],
    ["  3. Label every row -- do not skip any."],
    ["  4. When done, save the file. Do not edit any column except 'your_label'."],
]


def _redact_own_id(text: str, technique_id: str) -> str:
    return re.sub(re.escape(technique_id), "[ID REDACTED]", text, flags=re.IGNORECASE)


def build():
    if not os.path.exists(SOURCE_PATH):
        raise SystemExit(f"{SOURCE_PATH} not found.")

    with open(SOURCE_PATH, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    techniques = _load_attack_techniques()

    redacted_pairs = []
    for r in rows:
        tid = r["candidate_technique_id"]
        record = techniques.get(tid, {})
        bare_description = record.get("description") or r["candidate_technique_description"]
        # Strip the "Name: " prefix build_attack_pairs.py baked into this
        # field -- re-derive the bare description directly from the
        # snapshot rather than string-splitting the already-merged field.
        r["candidate_technique_description"] = bare_description

        before = r["alert_text"] + r["candidate_technique_description"]
        r["alert_text"] = _redact_own_id(r["alert_text"], tid)
        r["candidate_technique_description"] = _redact_own_id(r["candidate_technique_description"], tid)
        after = r["alert_text"] + r["candidate_technique_description"]
        if before != after:
            redacted_pairs.append(r["pair_id"])

    if redacted_pairs:
        print(f"Redacted self-referencing technique ID/name leak in {len(redacted_pairs)} pair(s): {redacted_pairs}")

    # --- private key file (not for the blind labeling pass) ---
    with open(KEY_CSV_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["pair_id", "alert_id", "candidate_technique_id"])
        for r in rows:
            w.writerow([r["pair_id"], r["alert_id"], r["candidate_technique_id"]])

    # --- blind sheet ---
    wb = Workbook()

    ws_instr = wb.active
    ws_instr.title = "Instructions"
    for row in INSTRUCTIONS:
        ws_instr.append(row)
    ws_instr["A1"].font = Font(bold=True, size=13)
    ws_instr.column_dimensions["A"].width = 100
    for row in ws_instr.iter_rows():
        for cell in row:
            cell.alignment = Alignment(wrap_text=False, vertical="top")

    ws = wb.create_sheet("ATT&CK Pairs")
    headers = ["pair_id", "alert_id", "evidence_snippet_anonymized", "attack_description_text", "your_label"]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)

    for r in rows:
        ws.append([r["pair_id"], r["alert_id"], r["alert_text"], r["candidate_technique_description"], ""])

    ws.column_dimensions["A"].width = 26
    ws.column_dimensions["B"].width = 16
    ws.column_dimensions["C"].width = 60
    ws.column_dimensions["D"].width = 60
    ws.column_dimensions["E"].width = 16
    ws.freeze_panes = "A2"
    for row in ws.iter_rows(min_row=2, min_col=3, max_col=4):
        for cell in row:
            cell.alignment = Alignment(wrap_text=True, vertical="top")

    dv = DataValidation(type="list", formula1='"relevant,not_relevant"', allow_blank=True, showDropDown=False)
    dv.error = "Choose relevant or not_relevant from the dropdown."
    dv.errorTitle = "Invalid label"
    ws.add_data_validation(dv)
    dv.add(f"E2:E{ws.max_row}")

    wb.save(BLIND_XLSX_PATH)

    print(f"Blind ATT&CK annotation sheet: {BLIND_XLSX_PATH} ({len(rows)} pairs)")
    print(f"Private reconciliation key (do NOT consult while labeling): {KEY_CSV_PATH}")


if __name__ == "__main__":
    build()

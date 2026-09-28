"""
experiments/evaluation/relevance_classifier_validation/build_attack_annotator2_sheet.py

Issue #43 (R4), supervisor follow-up on 2026-09-28: the CVE side already
has genuine independent double-annotation (n=80, kappa=1.0), but the
ATT&CK side only ever had a single annotator's pass
(attack_annotation_labeled.xlsx). This produces the second, independent
annotator's BLIND copy of the same 103 ATT&CK pairs, mirroring
build_annotator2_sheet.py's approach on the CVE side.

attack_annotation_labeled.xlsx must never be handed to annotator 2 as-is:
it carries annotator 1's `your_label` column. Its evidence and
description text are reused as-is here since they were already redacted
of the technique's own T-number by build_attack_annotation_sheet.py
(the original build already resolved the "redact ID, not name" question
-- see that script's docstring) -- so no re-redaction pass is needed,
just a check that no fresh leak has crept in since.

Also found and fixed here: 1/103 pairs (EDGE-MALDOC__T1204.002) leaked
its own sub-technique ID in the description text after all -- not as
"T1204.002" (which the original redaction did catch), but as
"T1204/002", the slash form MITRE's site uses for sub-technique URLs in
citation links (e.g. "...techniques/T1204/002"). The original build's
regex only matched the dot form. Confirmed this leak was present in
annotator 1's sheet too (a real gap worth a one-line disclosure
alongside the CVE side's analogous 2/80 leak, if this ever gets written
up), and it is the only pair among all 103 affected. Fixed here by also
redacting the slash-separated form for any technique ID containing a
dot.

Produces two files:
  attack_annotator2_pairs_BLIND.xlsx    -- give this to annotator 2. Only
      pair_id, alert_id, the alert evidence, and the redacted ATT&CK
      description text, plus a blank label column with a dropdown
      restricted to relevant/not_relevant. No technique ID, no
      annotator1 label anywhere in this file.
  attack_annotator1_and_key_HIDDEN.csv  -- NOT for annotator 2. Keeps
      candidate_technique_id + annotator1's your_label per pair_id, so
      a kappa/reconciliation script can compute inter-rater agreement
      once annotator 2's sheet comes back (same pattern as
      compute_inter_rater_agreement.py on the CVE side).

Usage:
    python -m experiments.evaluation.relevance_classifier_validation.build_attack_annotator2_sheet
"""

import csv
import os
import re

import openpyxl
from openpyxl import Workbook
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.styles import Font, Alignment

HERE = os.path.dirname(__file__)
LABELED_XLSX_PATH = os.path.join(HERE, "attack_annotation_labeled.xlsx")
KEY_SOURCE_CSV_PATH = os.path.join(HERE, "attack_annotation_key_HIDDEN.csv")
BLIND_XLSX_PATH = os.path.join(HERE, "attack_annotator2_pairs_BLIND.xlsx")
KEY_CSV_PATH = os.path.join(HERE, "attack_annotator1_and_key_HIDDEN.csv")

INSTRUCTIONS = [
    ["Relevance annotation -- ATT&CK pairs, Annotator 2 (blind pass)"],
    [],
    ["For each row, read the alert evidence and the technique description, then decide:"],
    ["does the technique description plausibly explain/match what the alert evidence describes?"],
    [],
    ["Put exactly one of these two values in the 'your_label' column (a dropdown is provided):"],
    ["  relevant      -- the description is a plausible match for the alert's behavior"],
    ["  not_relevant  -- the description does not match what the alert describes"],
    [],
    ["Rules:"],
    ["  1. Work independently. Do not discuss pairs with anyone else until both passes are submitted."],
    ["  2. Do not look up the technique online or try to identify its ATT&CK ID/name --"],
    ["     the identifier has been deliberately withheld so the label reflects the text alone,"],
    ["     not name recognition."],
    ["  3. Label every row -- do not skip any."],
    ["  4. When done, save the file and return it. Do not edit any column except 'your_label'."],
]


def _redact_own_id(text: str, technique_id: str) -> str:
    # MITRE's own site renders sub-technique URLs as e.g.
    # "https://attack.mitre.org/techniques/T1204/002" -- slash, not dot --
    # so a sub-technique ID like "T1204.002" must also be redacted in that
    # form, or a self-reference inside a citation URL leaks the real ID.
    text = re.sub(re.escape(technique_id), "[ID REDACTED]", text, flags=re.IGNORECASE)
    if "." in technique_id:
        slug = technique_id.replace(".", "/")
        text = re.sub(re.escape(slug), "[ID REDACTED]", text, flags=re.IGNORECASE)
    return text


def build():
    if not os.path.exists(LABELED_XLSX_PATH):
        raise SystemExit(f"{LABELED_XLSX_PATH} not found.")
    if not os.path.exists(KEY_SOURCE_CSV_PATH):
        raise SystemExit(f"{KEY_SOURCE_CSV_PATH} not found.")

    with open(KEY_SOURCE_CSV_PATH, encoding="utf-8") as f:
        technique_id_by_pair = {row["pair_id"]: row["candidate_technique_id"] for row in csv.DictReader(f)}

    wb_in = openpyxl.load_workbook(LABELED_XLSX_PATH)
    ws_in = wb_in["ATT&CK Pairs"]
    header = [c.value for c in next(ws_in.iter_rows(min_row=1, max_row=1))]
    idx = {name: i for i, name in enumerate(header)}

    rows = []
    for row in ws_in.iter_rows(min_row=2, values_only=True):
        if row[idx["pair_id"]] is None:
            continue
        rows.append({
            "pair_id": row[idx["pair_id"]],
            "alert_id": row[idx["alert_id"]],
            "evidence_snippet_anonymized": row[idx["evidence_snippet_anonymized"]],
            "attack_description_text": row[idx["attack_description_text"]],
            "annotator1_label": row[idx["your_label"]],
        })

    if len(rows) != len(technique_id_by_pair):
        raise SystemExit(
            f"Row count mismatch: {len(rows)} labeled rows vs {len(technique_id_by_pair)} key entries -- "
            "labeled sheet and key file are out of sync, stopping before producing a bad blind sheet."
        )

    # Re-check for a fresh ID leak (defense in depth -- the source text was
    # already redacted once by build_attack_annotation_sheet.py).
    redacted_pairs = []
    for r in rows:
        tid = technique_id_by_pair.get(r["pair_id"])
        if tid is None:
            raise SystemExit(f"pair_id {r['pair_id']!r} in labeled sheet has no entry in the key file.")
        before = (r["evidence_snippet_anonymized"] or "") + (r["attack_description_text"] or "")
        r["evidence_snippet_anonymized"] = _redact_own_id(r["evidence_snippet_anonymized"] or "", tid)
        r["attack_description_text"] = _redact_own_id(r["attack_description_text"] or "", tid)
        after = r["evidence_snippet_anonymized"] + r["attack_description_text"]
        if before != after:
            redacted_pairs.append(r["pair_id"])
    if redacted_pairs:
        print(f"Redacted a fresh self-referencing technique-ID leak in {len(redacted_pairs)} pair(s): {redacted_pairs}")
    else:
        print("No fresh ID leak found -- source text was already clean from the annotator-1 build.")

    # --- private key file (NOT for annotator 2) ---
    with open(KEY_CSV_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["pair_id", "alert_id", "candidate_technique_id", "annotator1_label"])
        for r in rows:
            w.writerow([r["pair_id"], r["alert_id"], technique_id_by_pair[r["pair_id"]], r["annotator1_label"]])

    # --- blind sheet for annotator 2 ---
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
        ws.append([
            r["pair_id"],
            r["alert_id"],
            r["evidence_snippet_anonymized"],
            r["attack_description_text"],
            "",
        ])

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

    print(f"Blind annotator-2 sheet: {BLIND_XLSX_PATH} ({len(rows)} pairs)")
    print(f"Private reconciliation key (do NOT share): {KEY_CSV_PATH}")


if __name__ == "__main__":
    build()

"""
experiments/evaluation/relevance_classifier_validation/build_annotator2_sheet.py

Issue #43 (R4), Task A.2: produces the second annotator's BLIND copy of the
80 CVE relevance pairs, plus a private key file for later reconciliation.

The existing pairs_to_label_with_suggestions.csv already holds the
completed single-annotator pass (its `human_label` column = annotator1).
That file must never be handed to annotator 2 as-is: it carries the real
CVE ID, the pipeline's own suggested_label/suggested_reason, and
annotator1's label -- any one of which would break blind annotation.

Also found and fixed here: 2/80 pairs (BAIT-077__CVE-2020-1472,
BAIT-071__CVE-2021-34527) leak their own CVE ID inside the raw NVD
description text itself -- some advisories self-reference their own ID
in prose (e.g. "...documented in CVE-2021-34527"), which the original
build never stripped. That's a real gap against Task A.1's anonymization
requirement, and it means annotator 1's original pass likely saw it too
for these 2 pairs (worth a one-line disclosure in the eventual §4.6
writeup). Fixed here by redacting each row's own candidate_cve_id
wherever it appears in the visible text, case-insensitively.

Produces two files:
  annotator2_cve_pairs_BLIND.xlsx   -- give this to annotator 2. Only
      pair_id, alert_id, the alert evidence, and the anonymized NVD
      description text, plus a blank label column with a dropdown
      restricted to relevant/not_relevant. No CVE ID, no suggestion, no
      annotator1 label anywhere in this file.
  annotator1_and_key_HIDDEN.csv     -- NOT for annotator 2. Keeps
      candidate_cve_id + annotator1's human_label per pair_id, so
      compute_cohen_kappa.py can reconcile the two independent passes
      once annotator 2's sheet comes back.

Usage:
    python -m experiments.evaluation.relevance_classifier_validation.build_annotator2_sheet
"""

import csv
import os
import re

from openpyxl import Workbook
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.styles import Font, Alignment

HERE = os.path.dirname(__file__)
SOURCE_PATH = os.path.join(HERE, "pairs_to_label_with_suggestions.csv")
BLIND_XLSX_PATH = os.path.join(HERE, "annotator2_cve_pairs_BLIND.xlsx")
KEY_CSV_PATH = os.path.join(HERE, "annotator1_and_key_HIDDEN.csv")

INSTRUCTIONS = [
    ["Relevance annotation -- Annotator 2 (blind pass)"],
    [],
    ["For each row, read the alert evidence and the vulnerability description, then decide:"],
    ["does the vulnerability description plausibly explain/match what the alert evidence describes?"],
    [],
    ["Put exactly one of these two values in the 'your_label' column (a dropdown is provided):"],
    ["  relevant      -- the description is a plausible match for the alert's behavior"],
    ["  not_relevant  -- the description does not match what the alert describes"],
    [],
    ["Rules:"],
    ["  1. Work independently. Do not discuss pairs with anyone else until both passes are submitted."],
    ["  2. Do not look up the vulnerability online or try to identify its CVE number/name --"],
    ["     the identifier has been deliberately withheld so the label reflects the text alone,"],
    ["     not name recognition."],
    ["  3. Label every row -- do not skip any."],
    ["  4. When done, save the file and return it. Do not edit any column except 'your_label'."],
]


def _redact_own_id(text: str, cve_id: str) -> str:
    return re.sub(re.escape(cve_id), "[ID REDACTED]", text, flags=re.IGNORECASE)


def build():
    if not os.path.exists(SOURCE_PATH):
        raise SystemExit(f"{SOURCE_PATH} not found.")

    with open(SOURCE_PATH, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    redacted_pairs = []
    for r in rows:
        before = r["alert_text"] + r["candidate_cve_description"]
        r["alert_text"] = _redact_own_id(r["alert_text"], r["candidate_cve_id"])
        r["candidate_cve_description"] = _redact_own_id(r["candidate_cve_description"], r["candidate_cve_id"])
        after = r["alert_text"] + r["candidate_cve_description"]
        if before != after:
            redacted_pairs.append(r["pair_id"])
    if redacted_pairs:
        print(f"Redacted self-referencing CVE-ID leak in {len(redacted_pairs)} pair(s): {redacted_pairs}")

    # --- private key file (NOT for annotator 2) ---
    with open(KEY_CSV_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["pair_id", "alert_id", "candidate_cve_id", "annotator1_label"])
        for r in rows:
            w.writerow([r["pair_id"], r["alert_id"], r["candidate_cve_id"], r["human_label"]])

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

    ws = wb.create_sheet("CVE Pairs")
    headers = ["pair_id", "alert_id", "evidence_snippet_anonymized", "nvd_description_text", "your_label"]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)

    for r in rows:
        ws.append([
            r["pair_id"],
            r["alert_id"],
            r["alert_text"],
            r["candidate_cve_description"],
            "",
        ])

    ws.column_dimensions["A"].width = 22
    ws.column_dimensions["B"].width = 12
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

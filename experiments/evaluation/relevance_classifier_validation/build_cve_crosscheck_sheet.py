"""
experiments/evaluation/relevance_classifier_validation/build_cve_crosscheck_sheet.py

Issue #43 (R4), Part A -- degraded-scope fallback the issue's own "Risks
& Mitigations" section names explicitly: "Annotator time unavailable
(you can't find 2nd annotator): Degrade to 'single annotator + 20% blind
cross-check by supervisor'. Report kappa with n=0.2xN bootstrap."

No second independent annotator is being recruited. Instead, the same
person who will do the labeling (not annotator 1, who already labeled
all 80 pairs and whose labels are frozen in
pairs_to_label_with_suggestions.csv) blind-labels a 20% SAMPLE of the 80
pairs -- stratified 8 positive-by-construction / 8 negative-by-construction
(matching the full set's exact 40/40 split, so the reduced sample isn't
accidentally skewed) -- with a fixed seed for reproducibility. Reuses
build_annotator2_sheet.py's exact blinding/redaction logic (hide the CVE
ID, strip any self-referencing ID leak from the NVD description text)
rather than duplicating it with any drift.

Produces:
  cve_crosscheck_BLIND.xlsx        -- the 16-pair blind sheet to fill in.
  cve_crosscheck_key_HIDDEN.csv    -- pair_id, alert_id, candidate_cve_id,
      annotator1_label for exactly those 16 pairs (not for the labeler --
      compute_cohen_kappa.py reconciles against this once filled in).

Usage:
    python -m experiments.evaluation.relevance_classifier_validation.build_cve_crosscheck_sheet
"""

import csv
import os
import random
import re

from openpyxl import Workbook
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.styles import Font, Alignment

import json

HERE = os.path.dirname(__file__)
SOURCE_PATH = os.path.join(HERE, "pairs_to_label_with_suggestions.csv")
CONSTRUCTION_KEY_PATH = os.path.join(HERE, "construction_key.json")
BLIND_XLSX_PATH = os.path.join(HERE, "cve_crosscheck_BLIND.xlsx")
KEY_CSV_PATH = os.path.join(HERE, "cve_crosscheck_key_HIDDEN.csv")

SAMPLE_FRACTION = 0.2
RANDOM_SEED = 20260926  # date this was built, for reproducibility -- not a secret

INSTRUCTIONS = [
    ["Relevance annotation -- blind cross-check (20% sample, issue #43/R4 degraded-scope fallback)"],
    [],
    ["For each row, read the alert evidence and the vulnerability description, then decide:"],
    ["does the vulnerability description plausibly explain/match what the alert evidence describes?"],
    [],
    ["Put exactly one of these two values in the 'your_label' column (a dropdown is provided):"],
    ["  relevant      -- the description is a plausible match for the alert's behavior"],
    ["  not_relevant  -- the description does not match what the alert describes"],
    [],
    ["Rules:"],
    ["  1. Work independently -- don't consult the original (non-blind) pairs file while labeling this."],
    ["  2. Do not look up the vulnerability online or try to identify its CVE number/name --"],
    ["     the identifier has been deliberately withheld so the label reflects the text alone,"],
    ["     not name recognition."],
    ["  3. Label every row -- do not skip any."],
    ["  4. When done, save the file. Do not edit any column except 'your_label'."],
]


def _redact_own_id(text: str, cve_id: str) -> str:
    return re.sub(re.escape(cve_id), "[ID REDACTED]", text, flags=re.IGNORECASE)


def build():
    if not os.path.exists(SOURCE_PATH):
        raise SystemExit(f"{SOURCE_PATH} not found.")

    with open(SOURCE_PATH, encoding="utf-8") as f:
        rows = {r["pair_id"]: r for r in csv.DictReader(f)}

    with open(CONSTRUCTION_KEY_PATH, encoding="utf-8") as f:
        construction_key = json.load(f)

    positive_ids = sorted(pid for pid, v in construction_key.items() if v["intended"] == "positive")
    negative_ids = sorted(pid for pid, v in construction_key.items() if v["intended"] == "negative")
    n_each = round(len(positive_ids) * SAMPLE_FRACTION)

    rng = random.Random(RANDOM_SEED)
    sample_ids = sorted(rng.sample(positive_ids, n_each) + rng.sample(negative_ids, n_each))
    sample_rows = [rows[pid] for pid in sample_ids]
    rng.shuffle(sample_rows)

    redacted_pairs = []
    for r in sample_rows:
        before = r["alert_text"] + r["candidate_cve_description"]
        r["alert_text"] = _redact_own_id(r["alert_text"], r["candidate_cve_id"])
        r["candidate_cve_description"] = _redact_own_id(r["candidate_cve_description"], r["candidate_cve_id"])
        after = r["alert_text"] + r["candidate_cve_description"]
        if before != after:
            redacted_pairs.append(r["pair_id"])
    if redacted_pairs:
        print(f"Redacted self-referencing CVE-ID leak in {len(redacted_pairs)} pair(s): {redacted_pairs}")

    # --- private key file (not for the blind labeling pass) ---
    with open(KEY_CSV_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["pair_id", "alert_id", "candidate_cve_id", "annotator1_label"])
        for r in sample_rows:
            w.writerow([r["pair_id"], r["alert_id"], r["candidate_cve_id"], r["human_label"]])

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

    ws = wb.create_sheet("CVE Cross-check (20%)")
    headers = ["pair_id", "alert_id", "evidence_snippet_anonymized", "nvd_description_text", "your_label"]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)

    for r in sample_rows:
        ws.append([r["pair_id"], r["alert_id"], r["alert_text"], r["candidate_cve_description"], ""])

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

    print(f"Blind cross-check sheet: {BLIND_XLSX_PATH} ({len(sample_rows)} pairs, "
          f"{n_each} positive-by-construction / {n_each} negative-by-construction)")
    print(f"Private reconciliation key (do NOT consult while labeling): {KEY_CSV_PATH}")


if __name__ == "__main__":
    build()

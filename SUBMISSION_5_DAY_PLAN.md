# 5-Day Submission Plan

Submission deadline: 15 May 2026

Use 15 May only for final upload checks. Finish the real work by 14 May.

## Day 1 - 10 May 2026: GitHub and Clean Source

- Put only the final clean source code into the GitHub repository.
- Remove generated files such as `__pycache__`, logs, VM keys, database dumps, and temporary report assets.
- Add `README.md`, `.gitignore`, and this 5-day plan.
- Verify the repository contains `src`, `grafana`, and `requirements.txt`.
- Make the first clean Git commit after confirming the correct Git username and email.

Checklist:

- `git status --short`
- `git add .`
- `git commit -m "Prepare Cowrie ML SOC source submission"`
- `git push -u origin main`

## Day 2 - 11 May 2026: Full System Test

- Run MySQL and confirm the `cowrie_prod` schema exists.
- Run Cowrie on the VM and confirm it writes JSON events.
- Run ETL ingestion and confirm new rows in `attackers`, `sessions`, and `auth_attempts`.
- Run geolocation and confirm countries appear in the dashboard.
- Run K-Means clustering and confirm `cluster_group` and `risk_score` update.
- Run forecasting and confirm 24 prediction rows are created for the latest run.
- Start FastAPI and test `/`, `/attackers`, `/attackers/clusters`, `/threats/active`, and `/predictions`.
- Open Grafana and confirm panels update with live or controlled Cowrie attack data.

Evidence to capture:

- Cowrie JSON log screenshot.
- MySQL table count screenshot.
- API endpoint screenshot.
- Grafana dashboard screenshot.

## Day 3 - 12 May 2026: Final Report Completion

- Add the GitHub repository link to the final report appendix.
- Add the source-code submission link required by the guideline.
- Add final dashboard screenshots.
- Add a short explanation of the AI/ML parts: K-Means risk clustering and next-24-hour prediction.
- Export a draft PDF named `10953287_Final_Report.pdf`.

Evidence to capture:

- Report cover page.
- Appendix source-code link.
- ML output screenshot.

## Day 4 - 13 May 2026: Viva Demo Practice

- Prepare a 5 to 7 minute demo flow:
  1. Show Cowrie running on the VM.
  2. Run authorized brute-force test attempts against the Cowrie port.
  3. Show Cowrie JSON logs being created.
  4. Run or show ETL ingestion.
  5. Show MySQL rows updated.
  6. Show risk clustering and prediction output.
  7. Show Grafana auto-refreshing.
- Practice explaining why the dashboard may show other countries: public honeypots can receive real internet scans from outside attackers.
- Prepare answers for "How does the ML work?", "Why K-Means?", and "What does future prediction mean?"

Evidence to capture:

- Short viva script.
- Final dashboard screenshot after demo attack.
- API `/predictions` screenshot.

## Day 5 - 14 May 2026: Final Packaging and Backup

- Confirm GitHub repository is pushed and visible.
- Confirm final PDF opens correctly.
- Confirm final report contains the source-code link.
- Upload final report and source link to the required submission location.
- Keep backups on Desktop, Downloads, OneDrive, and GitHub.
- Do one final dry run of the viva demo.

Final checks:

- Source code link works.
- PDF file name is correct.
- Report opens on another device or browser.
- Dashboard screenshots are included.
- No secrets or VM keys are committed.

## Submission Day - 15 May 2026

- Do not make major code changes.
- Recheck upload status.
- Keep GitHub, final PDF, and dashboard demo ready for questions.

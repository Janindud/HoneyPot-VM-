# 4-Day Submission Plan

Submission deadline: 15 May 2026

This plan spreads the remaining work across four working days. It does not include a separate viva-practice day or a separate submit-only day.

## Day 1 - 11 May 2026: GitHub and Clean Source

- Confirm the GitHub repository uses the correct `Janindud` account.
- Push the latest clean source code to GitHub.
- Confirm the repository is visible and contains only final source files.
- Check that `src`, `grafana`, `requirements.txt`, `README.md`, `.gitignore`, and this plan file are present.
- Confirm no VM keys, raw Cowrie logs, database dumps, or local cache files are committed.
- Copy the GitHub repository link for the final report appendix.

Evidence to capture:

- GitHub repository page.
- Git commit history.
- Clean repository file list.

## Day 2 - 12 May 2026: Cowrie, ETL, and Database Test

- Run Cowrie on the VM and confirm it writes JSON log events.
- Generate controlled authorized test login attempts against the Cowrie port.
- Run ETL ingestion and confirm new rows appear in `attackers`, `sessions`, and `auth_attempts`.
- Run geolocation and confirm attacker countries are populated.
- Check MySQL table counts and latest records.
- Confirm Cowrie JSON events are converted into database records correctly.

Evidence to capture:

- Cowrie JSON log output.
- MySQL `attackers`, `sessions`, and `auth_attempts` table counts.
- Latest attacker records with country values.

## Day 3 - 13 May 2026: ML, API, and Grafana Evidence

- Run K-Means clustering and confirm `cluster_group` and `risk_score` update.
- Run the forecast pipeline and confirm the latest 24 prediction rows are created.
- Start FastAPI and test `/`, `/attackers`, `/attackers/clusters`, `/threats/active`, and `/predictions`.
- Open Grafana and confirm dashboard panels update from Cowrie pipeline data.
- Capture dashboard screenshots showing attackers, countries, risk clusters, and future attack prediction.

Evidence to capture:

- K-Means cluster output.
- Forecast prediction rows.
- FastAPI endpoint output.
- Grafana dashboard screenshots.

## Day 4 - 14 May 2026: Final Report, Export, and Backup

- Add the GitHub repository link to the final report appendix.
- Add the required source-code submission link.
- Add final dashboard screenshots.
- Polish the AI/ML explanation for K-Means risk clustering and next-24-hour prediction.
- Export the final report as `10953287_Final_Report.pdf`.
- Confirm the final PDF opens correctly.
- Confirm the GitHub/source link works from the report.
- Back up the final report, source folder, and screenshots.
- Do one full end-to-end check: Cowrie log to ETL, MySQL, ML, API, and Grafana output.

Final checks:

- Source code link works.
- PDF file name is correct.
- Report opens correctly.
- Dashboard screenshots are included.
- No secrets, VM keys, raw logs, or database dumps are committed.

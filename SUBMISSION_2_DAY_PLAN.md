# 2-Day Submission Plan

Submission deadline: 15 May 2026

This plan removes the separate viva-practice day and the separate submit-only day. The remaining work is divided into two focused working days.

## Day 1 - 11 May 2026: Source, VM, Pipeline, and Dashboard

- Push the clean source code repository to GitHub using the correct `Janindud` account.
- Confirm the GitHub repository is visible and contains only the final source files.
- Run MySQL and confirm the `cowrie_prod` database schema exists.
- Run Cowrie on the VM and confirm it writes JSON log events.
- Run ETL ingestion and confirm new rows appear in `attackers`, `sessions`, and `auth_attempts`.
- Run geolocation and confirm attacker countries appear.
- Run K-Means clustering and confirm `cluster_group` and `risk_score` update.
- Run the forecast pipeline and confirm the latest 24 prediction rows are created.
- Start FastAPI and test `/`, `/attackers`, `/attackers/clusters`, `/threats/active`, and `/predictions`.
- Open Grafana and confirm dashboard panels update from real or controlled Cowrie data.

Evidence to capture:

- GitHub repository page.
- Cowrie JSON log output.
- MySQL table counts.
- FastAPI endpoint output.
- Grafana dashboard after pipeline update.

## Day 2 - 12 May 2026: Final Report, Evidence, and Backup

- Add the GitHub repository link to the final report appendix.
- Add the required source-code submission link.
- Add final dashboard screenshots.
- Add or polish the AI/ML explanation for K-Means risk clustering and next-24-hour prediction.
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

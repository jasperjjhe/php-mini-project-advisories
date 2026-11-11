# php-mini-project-advisories

Public security advisories for freely distributed PHP mini-projects, published as part of coordinated disclosure. Each file documents one vulnerability: root cause with file and line references, non-weaponized proof, classification (CWE, CVSS), deduplication status and a suggested fix.

| Advisory | Product | Class |
|---|---|---|
| A1-pos-pharmacy-login-sqli.md | code-projects POS Pharmacy System 1.0 | SQL Injection (CWE-89) |
| A2-pos-pharmacy-missing-auth.md | code-projects POS Pharmacy System 1.0 | Missing Authorization (CWE-862) |
| B1-hotel-reservation-missing-auth.md | Campcodes Online Hotel Reservation System 1.0 | Missing Authorization (CWE-862) |

Vendors were contacted on 2026-11-10. Entries were checked against NVD and the VulDB database prior to publication; dedup status is stated per file.

## VulDB moderation supplements (prepared, not yet sent)

These files correct or extend claims in the VulDB submissions (tickets 1086441, 1085347, 1085346); they are prepared for the moderation team and will be supplied when a ticket is queried. Read them alongside the corresponding advisory:

| Supplement | For ticket | Contents |
|---|---|---|
| vuldb-1086441-supplement.txt | 1086441 (A1) | corrected clean() line references; failed-login response shape (raw query echo + "Query failed") |
| vuldb-1085347-supplement.txt | 1085347 (A2) | corrected auth.php description (main/auth.php checks SESS_MEMBER_ID); savesales line refs (due 14-15, cash 26-27) |
| vuldb-1085346-supplement.txt | 1085346 (B1) | corrected PoC (upload proof on add_query_room.php; injection proof on edit_query_room.php); two additional unguarded endpoints; backup.php chain; severity display note |

## Revision history

- 2026-11-10: initial publication (A1, A2, B1)
- 2026-11-11: corrections after full source re-verification (see supplements)

Contact: jasperjjhe (at) users.noreply.github.com
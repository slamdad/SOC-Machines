# TryHackMe: Slingshot — SOC Investigation Walkthrough

## Scenario

Slingway Inc., an e-commerce toy company, detected suspicious activity on its web server and possible unauthorized database modifications. Using an Elastic Stack instance (Kibana, `apache_logs` Data View), the goal is to reconstruct the attack timeline and answer:

- What reconnaissance and enumeration techniques were used?
- What vulnerabilities were exploited on the web server?
- How did the attacker gain administrative access?
- What sensitive data was accessed or exfiltrated?

Investigation window: `Jul 26, 2023 @ 00:00:00.000 → now`

## Tools Used
- Kibana Discover (KQL queries, field value breakdowns)
- CyberChef (Base64 decoding)

---

## Phase 1 — Reconnaissance & Enumeration

### Identifying the Attacker's IP
Opened the `source.ip` (client IP) field in the Discover sidebar and checked the **top values breakdown**. One IP stood out by a large margin in total request volume compared to normal traffic — consistent with automated scanning/enumeration rather than organic browsing.

**Attacker IP:** `10.0.2.15`

### First Scanner Used
Filtered on the attacker's IP and sorted by `@timestamp` ascending to see the earliest activity. The first tool to hit the server, identified by its User-Agent string, was the **Nmap Scripting Engine (NSE)** — consistent with an initial recon/service-fingerprinting pass before deeper enumeration began.

### Directory Enumeration Tool
Continuing forward chronologically from the Nmap activity, the traffic shifted to a large burst of sequential path requests — classic directory brute-forcing behavior. The `User-Agent` field on these requests identified the tool directly.

**User-Agent:** `Mozilla/5.0 (Gobuster)`

### Total 404 Responses During Enumeration
Filtered to the attacker's IP + Gobuster's User-Agent, then used the `response`/`http.response.status_code` field breakdown filtered to `404` to get the count.

**Total 404s:** `1867`

### Flag Discovered in a Directory
While reviewing the Gobuster enumeration results, filtered out 404s to isolate valid (existing) paths. One request returned a flag embedded directly in the query string:

```
GET /backups/?flag=a76637b62ea99acda12f5859313f539a HTTP/1.1
User-Agent: Mozilla/5.0 (Gobuster)
```

**Flag:** `a76637b62ea99acda12f5859313f539a`

### Admin Login Page Discovered
Continued reviewing non-404 Gobuster results in timestamp order. The enumeration activity stops at the point the attacker locates a valid login endpoint — the last meaningful hit before the traffic pattern shifts to authentication attempts.

**Discovered path:** `/admin/admin-login.php`

---

## Phase 2 — Exploitation

### Brute-Force Tool
Filtered to the attacker's IP and the discovered login path (`/admin/admin-login.php`). Traffic shifted to a burst of repeated `POST` requests against the same endpoint — a brute-force pattern. The `User-Agent` on these requests identified the tool.

**User-Agent:** `Mozilla/4.0 (Hydra)`

### Successful Credentials
Followed the Hydra POST requests chronologically to the point where the pattern stops (repeated failed attempts, then a successful one — usually indicated by a change in response code/size, or a redirect to an authenticated area). The successful request contained Base64-encoded Basic Auth credentials, decoded via CyberChef:

- **Base64:** `YWRtaW46dGh4MTEzOA==`
- **Decoded:** `admin:thx1138`

**Credentials:** `admin:thx1138`

### Web Shell Upload
Searched with the KQL wildcard `*upload.php*` to locate all activity involving the upload endpoint. Among the results, one request to `/admin/upload.php` contained an embedded flag confirming the malicious file upload.

**Flag:** `THM{ecb012e53a58818cbd17a924769ec447}`

Reviewing surrounding `upload.php` requests showed the attacker using it to plant a PHP-based reverse shell / web shell, enabling remote command execution on the server.

---

## Phase 3 — Post-Exploitation

### First Web Shell Command
With web shell access established, the natural first move for an attacker is a basic identity check. Reviewing requests immediately following the successful upload confirmed the first command executed was:

**Command:** `whoami`

### LFI — Database Credentials
Reviewing further web shell/PHP-related activity in the logs revealed a request pulling a configuration file containing database connection details via Local File Inclusion.

**File accessed via LFI:** `config-db.php`

### Database Exported via phpMyAdmin
Searched for `phpmyadmin` activity in the logs. Found a request corresponding to a database export/dump action. Given the sensitivity of the data involved (matches the incident's "unauthorized database modification" concern), the exported database was:

**Database name:** `customer_credit_cards`

### Flag Inserted via `import.php`
Searched with the KQL wildcard `*import.php*` to find where the attacker used phpMyAdmin's import functionality to write data back into the database. The relevant SQL insert contained an encoded value, decoded via CyberChef:

```sql
'000', 'c6aa3215a7d519eeb40a660f3b76e64c', '000', '000'
```

**Flag:** `c6aa3215a7d519eeb40a660f3b76e64c`

---

## Attack Timeline Summary

| Phase | Action | Key Evidence |
|---|---|---|
| Recon | NSE scan against web server | User-Agent: Nmap Scripting Engine |
| Enumeration | Gobuster directory brute-force | 1867× 404s, flag in `/backups/`, discovered `/admin/admin-login.php` |
| Exploitation | Hydra brute-force on admin login | UA: `Mozilla/4.0 (Hydra)`, creds `admin:thx1138` |
| Access | Web shell uploaded via `/admin/upload.php` | Flag: `THM{ecb012e53a58818cbd17a924769ec447}` |
| Post-Exploitation | Web shell command execution | First command: `whoami` |
| Post-Exploitation | LFI to read `config-db.php` | DB credentials exposed |
| Exfiltration | DB export via phpMyAdmin | `customer_credit_cards` |
| Post-Exploitation | Data written back via `import.php` | Flag: `c6aa3215a7d519eeb40a660f3b76e64c` |

## Answers Recap

| # | Question | Answer |
|---|---|---|
| 1 | Attacker's IP | `10.0.2.15` |
| 2 | First scanner | Nmap Scripting Engine |
| 3 | Enum tool User-Agent | `Mozilla/5.0 (Gobuster)` |
| 4 | Total 404s during enumeration | `1867` |
| 5 | Flag in enumerated directory | `a76637b62ea99acda12f5859313f539a` |
| 6 | Discovered login page | `/admin/admin-login.php` |
| 7 | Brute-force tool User-Agent | `Mozilla/4.0 (Hydra)` |
| 8 | Admin credentials | `admin:thx1138` |
| 9 | Flag in uploaded file | `THM{ecb012e53a58818cbd17a924769ec447}` |
| 10 | First web shell command | `whoami` |
| 11 | File accessed via LFI | `config-db.php` |
| 12 | Exported database name | `customer_credit_cards` |
| 13 | Flag inserted via `import.php` | `c6aa3215a7d519eeb40a660f3b76e64c` |

## Methodology Notes (for future investigations)

- **Finding the attacker fast:** field-value breakdown on `source.ip`/`client.ip` sorted by count is usually the quickest first move in noisy access logs — automated tooling generates disproportionate traffic volume compared to real users.
- **User-Agent is a goldmine:** many offensive tools (Gobuster, Hydra, Nmap NSE) leave identifiable default User-Agent strings unless the attacker bothers to spoof them. Always pull this field into your table early.
- **KQL wildcard searches** (`*upload.php*`, `*import.php*`) are effective for jumping straight to activity on a specific endpoint once you know it's relevant, rather than manually scrolling timestamp by timestamp.
- **Chronological pivoting:** once you've isolated the attacker's IP, sorting ascending by `@timestamp` turns the investigation into a readable story — recon → enum → exploit → post-exploit — and makes it obvious where one phase ends and the next begins (e.g. enumeration traffic literally stops once a target endpoint is found).
- **Always decode encoded values** (Base64 creds, encoded flags) through CyberChef before concluding a field is "just noise" — attackers often hide meaningful data in what looks like garbage strings.
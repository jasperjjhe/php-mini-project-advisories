# code-projects POS Pharmacy System 1.0 - SQL injection in login.php

- Product page: https://www.code-projects.org/pos-pharmacy-system/ (PHP/MySQL mini-project, distributed as a free download)
- Reported: 2026-11-10, to the vendor via the site contact channel
- Researcher: Jasper He (jasperjjhe)
- Status: unpublished, awaiting vendor response; will be updated with any fix

## Summary

The login flow of POS Pharmacy System 1.0 concatenates the POST parameters `username` and `password` into the SQL query without escaping or parameterization. An unauthenticated attacker can authenticate as any user, including the administrator, with a trivially crafted username.

## Details

`index.php` posts the login form to `login.php`. There, the `clean()` helper (defined at line 25, applied at lines 34-35) only applies legacy magic-quotes-style slash stripping, which does not neutralize single quotes:

```php
$login = clean($_POST['username']);
$password = clean($_POST['password']);
$qry = "SELECT * FROM user WHERE username='$login' AND password='$password'";
```

The query is built at login.php line 56 and executed at line 57; the raw SQL is echoed back to the client on failed logins (lines 77-79: `print $qry` followed by "Query failed"), which confirms the injection context to an attacker.

## Proof

Authentication bypass as administrator:

```
POST /login.php
username=admin' -- &password=x
```

Confirmation on failed logins: the raw SQL query is echoed back to the client followed by "Query failed" (lines 77-79), showing the injection context directly.

## Classification

- CWE-89 (SQL Injection)
- CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)
- Affected file/parameter: login.php, `username` and `password` (POST)

## Deduplication

Checked 2026-11-09 against NVD (keyword search) and VulDB (API search). The only published entry for this product is CVE-2025-9921 (stored XSS in /main/products.php), which does not cover login.php. No prior SQL injection record exists for this product.

## Suggested fix

Use prepared statements (`mysqli` with bound parameters) for the credential query, remove the `print $qry` debug output, and drop the `clean()` helper.

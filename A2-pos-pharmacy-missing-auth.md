# code-projects POS Pharmacy System 1.0 - missing authorization on all /main/ action endpoints

- Product page: https://www.code-projects.org/pos-pharmacy-system/
- Reported: 2026-11-10, to the vendor via the site contact channel
- Researcher: Jasper He (jasperjjhe)
- Status: unpublished, awaiting vendor response; will be updated with any fix

## Summary

Approximately 36 PHP files under `/main/` never include the `auth.php` session
guard that the product's privileged pages are expected to use. Every
state-changing endpoint in that directory can be invoked by an unauthenticated
remote user: customer and supplier records can be deleted or modified, and
sales records can be fabricated.

## Details

`auth.php` in the product root checks `$_SESSION['username']` and is included
by the display pages under `/main/`, but the action handlers omit it. Examples
verified in the 1.0 source:

- `main/deletecustomer.php` - `DELETE FROM customer WHERE customer_id=$id`
  with `$_GET['id']` unescaped, no session check
- `main/deletesupplier.php`, `main/editcustomer.php` - same pattern
- `main/savesales.php` (lines 26-27) - inserts `$_POST['cash']` / `$_POST['due']`
  unescaped

A helper in `connect.php` (lines 14-17), `pq()`, wraps scalar values in single
quotes without escaping, which provides no injection protection and masks the
problem for developers reusing it.

## Proof

Delete customer record 1 with no session cookie:

```
GET /main/deletecustomer.php?id=1
```

SQL injection in the same endpoints (differential response):

```
GET /main/deletecustomer.php?id=1 and (select 1)=1
GET /main/deletecustomer.php?id=1 and (select 1)=2
```

## Classification

- CWE-862 (Missing Authorization); several endpoints also CWE-89
- CVSS v3.1 (anchor: unauthenticated destructive DELETE): AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)
- Affected files: main/deletecustomer.php, main/deletesupplier.php,
  main/editcustomer.php, main/savesales.php and siblings in the same
  directory sharing the same root cause

## Deduplication

Checked 2026-11-09 against NVD (keyword search) and VulDB (API search). The
only published entry for this product is CVE-2025-9921 (stored XSS in
/main/products.php). That record was scored CVSS 2.4 with PR:H on the
assumption that /main/ pages require admin access; this report shows those
endpoints lack the session guard entirely, so exploitation is unauthenticated.
No missing-authorization record exists for this product.

## Suggested fix

Include the `auth.php` guard (or an equivalent centralized check) at the top
of every file under `/main/`, replace `pq()` with prepared statements, and
cast identifiers to `intval()` before use in DELETE/UPDATE queries.

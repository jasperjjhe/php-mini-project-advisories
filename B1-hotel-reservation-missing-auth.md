# Campcodes Online Hotel Reservation System 1.0 - missing authentication on admin action endpoints

- Product page: https://www.campcodes.com/projects/php/online-hotel-reservation-system/ (PHP/MySQL mini-project, distributed as a free download)
- Reported: 2026-11-10, to the vendor via the site contact channel
- Researcher: Jasper He (jasperjjhe)
- VulDB ticket: 1085346 (filed 2026-11-10 from an earlier draft of this advisory; see Revision history below - this page is the corrected, authoritative version)
- Status: unpublished, awaiting vendor response; will be updated with any fix

## Revision history

- 2026-11-10: initial version (matches the VulDB submission).
- 2026-11-11: corrections after full source re-verification. (1) Proof split: add_query_room.php demonstrates the unauthenticated upload (the INSERT there never runs - the handler includes nothing and $conn is undefined); the SQLi demonstration moved to edit_query_room.php (includes connect.php itself, no session check). The ticket's PoC text predates this correction and still describes the INSERT on add_query_room.php. (2) confirm_reserve.php removed from the affected list (it does include validate.php). (3) The filename claim corrected: $photo and $photo_name pass through addslashes() before insertion - room_type and price remain the raw injectables. (4) Two additional unguarded endpoints added: admin/delete_room.php, admin/edit_query_account.php. (5) A supplement for the VulDB moderation team is prepared in this repository: vuldb-1085346-supplement.txt.

## Summary

The admin display pages of Online Hotel Reservation System 1.0 include `admin/validate.php`, which checks `$_SESSION['admin_id']`. The state-changing action endpoints do not include it. An unauthenticated remote user can add and edit rooms (including uploading arbitrary files), delete administrator accounts, delete pending transactions, and change reservation states.

## Details

Verified in the current distribution (mirror HEAD 2026-10-01):

- `admin/add_query_room.php` - no session check; stores an uploaded file under `/photo/` with the client-supplied name (`move_uploaded_file`, no type or extension validation enforced; the `getimagesize()` result is assigned but never read) and inserts `$_POST['room_type']` and `$_POST['price']` into SQL unescaped (the file name passes through `addslashes()` before insertion)
- `admin/edit_query_room.php` - same pattern for updating rooms
- `admin/delete_account.php?admin_id=1` - deletes a row from the admin table
- `admin/delete_pending.php`, `admin/checkout_query.php`, `admin/save_form.php` - DELETE/UPDATE on transaction and reservation records, no session check (`admin/confirm_reserve.php` does include `validate.php` at line 3 and is not part of this issue)
- `admin/delete_room.php` - deletes a room row via `mysql_query` DELETE keyed on `$_REQUEST[room_id]`; includes only `connect.php` (line 2), no session check - verified sibling of the same pattern
- `admin/edit_query_account.php` - updates the admin table from `$_POST` fields keyed on `$_REQUEST[admin_id]`; includes only `connect.php` (line 2), no session check

The application implements no anti-CSRF tokens anywhere, so the same requests can be issued cross-site against an authenticated admin.

## Proof

Two complementary primitives, both reachable with no session.

**Unauthenticated file upload** - `admin/add_query_room.php` accepts the add-room POST with no cookie. The guarded form page `admin/add_room.php` includes `add_query_room.php` as its POST handler, but the handler itself includes nothing at all - it uses `$conn` from a `connect.php` it never loads, and performs no session check. A direct POST lands the uploaded file in `/photo/` (via `move_uploaded_file`, line 8) with the client-supplied name and no extension or type validation:

```
POST /admin/add_query_room.php
  add_room=1&room_type=x'&price=1        (file field: any file)
```

The uploaded file is written before the query runs. The INSERT at line 9 then fatals on the undefined `$conn` (no database connection is ever established), so this endpoint demonstrates the upload and the missing authorization - not the injection.

**Unauthenticated SQL injection** - `admin/edit_query_room.php` includes `connect.php` itself and has no session check, so a direct POST reaches the UPDATE and surfaces the MySQL error through `die(mysqli_error())`:

```
POST /admin/edit_query_room.php
  edit_room=1&room_id=1&room_type=x'&price=1
```

Together the two endpoints demonstrate unauthenticated upload plus unauthenticated injection behind the same missing-authorization root cause.

## Classification

- CWE-862 (Missing Authorization) on all endpoints listed; add_query_room.php also CWE-434 (Unrestricted File Upload); edit_query_room.php also CWE-89 (SQL Injection)
- CVSS v3.1 (anchor: unauthenticated upload + injection): AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)
- Affected files/parameters: admin/add_query_room.php (photo, room_type, price), admin/edit_query_room.php, admin/delete_account.php (admin_id), admin/delete_pending.php (transaction_id), admin/checkout_query.php, admin/save_form.php, admin/delete_room.php (room_id), admin/edit_query_account.php (admin_id)

## Deduplication

Checked 2026-11-09 against NVD (keyword search) and VulDB (API search; 46 entries for the "Online Hotel Reservation System" family enumerated). No published entry covers add_query_room.php or edit_query_room.php (API searches return zero items). Entries under sibling vendor labels of the same codebase cover other files and/or only the injection symptom: CVE-2025-6578 (delete_account.php SQLi), CVE-2025-6451 (delete_pending.php SQLi), CVE-2025-6450 (confirm_reserve.php SQLi), CVE-2025-6449 (checkout_query.php SQLi), CVE-2025-8378-8382 (Campcodes: admin/index.php login SQLi, admin/edit_room.php upload+SQLi, add_query_account.php XSS, add_reserve.php SQLi), CVE-2025-13169 (add_query_reserve.php SQLi). None of these disclose the missing authentication root cause or the unauthenticated file upload.

## Suggested fix

Require `admin/validate.php` in every action endpoint, validate uploads (extension + MIME allowlist, randomized stored filenames outside the webroot or with an .htaccess deny), use prepared statements, and add CSRF tokens to all state-changing forms.

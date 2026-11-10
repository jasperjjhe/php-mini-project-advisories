# Campcodes Online Hotel Reservation System 1.0 - missing authentication on admin action endpoints

- Product page: https://www.campcodes.com/projects/php/online-hotel-reservation-system/ (PHP/MySQL mini-project, distributed as a free download)
- Reported: 2026-11-10, to the vendor via the site contact channel
- Researcher: Jasper He (jasperjjhe)
- Status: unpublished, awaiting vendor response; will be updated with any fix

## Summary

The admin display pages of Online Hotel Reservation System 1.0 include
`admin/validate.php`, which checks `$_SESSION['admin_id']`. The
state-changing action endpoints do not include it. An unauthenticated remote
user can add and edit rooms (including uploading arbitrary files), delete
administrator accounts, delete pending transactions, and change reservation
states.

## Details

Verified in the current distribution (mirror HEAD 2026-10-01):

- `admin/add_query_room.php` - no session check; stores an uploaded file under
  `/photo/` with the client-supplied name (`move_uploaded_file` with no type or
  extension validation) and inserts `$_POST['room_type']`, `$_POST['price']`
  and the file name into SQL unescaped
- `admin/edit_query_room.php` - same pattern for updating rooms
- `admin/delete_account.php?admin_id=1` - deletes a row from the admin table
- `admin/delete_pending.php`, `admin/checkout_query.php`,
  `admin/save_form.php`, `admin/confirm_reserve.php` - DELETE/UPDATE on
  transaction and reservation records, no session check

The application implements no anti-CSRF tokens anywhere, so the same requests
can be issued cross-site against an authenticated admin.

## Proof

The add-room endpoint renders and accepts submissions without any cookie:

```
GET /admin/add_query_room.php            (form renders, no session)
POST /admin/add_query_room.php
  add_room=1&room_type=x'&price=1        (file field: any file)
```

The INSERT fails with a MySQL error surfaced by `die(mysqli_error())`,
confirming injection; the uploaded file is written to `/photo/` before the
query runs. File type is never validated, so any extension is accepted.

## Classification

- CWE-862 (Missing Authorization) on all endpoints listed;
  add_query_room.php / edit_query_room.php also CWE-434 (Unrestricted
  File Upload) and CWE-89 (SQL Injection)
- CVSS v3.1 (anchor: unauthenticated upload + injection): AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)
- Affected files/parameters: admin/add_query_room.php (photo, room_type,
  price), admin/edit_query_room.php, admin/delete_account.php (admin_id),
  admin/delete_pending.php (transaction_id), admin/checkout_query.php,
  admin/save_form.php, admin/confirm_reserve.php

## Deduplication

Checked 2026-11-09 against NVD (keyword search) and VulDB (API search; 46
entries for the "Online Hotel Reservation System" family enumerated). No
published entry covers add_query_room.php or edit_query_room.php (API searches
return zero items). Entries under sibling vendor labels of the same codebase
cover other files and/or only the injection symptom in some of the files
listed above: CVE-2025-6578 (delete_account.php SQLi), CVE-2025-6451
(delete_pending.php SQLi), CVE-2025-6450 (confirm_reserve.php SQLi),
CVE-2025-6449 (checkout_query.php SQLi), CVE-2025-8378-8382 (Campcodes:
admin/index.php login SQLi, admin/edit_room.php upload+SQLi,
add_query_account.php XSS, add_reserve.php SQLi), CVE-2025-13169
(add_query_reserve.php SQLi). None of these disclose the missing
authentication root cause or the unauthenticated file upload.

## Suggested fix

Require `admin/validate.php` in every action endpoint, validate uploads
(extension + MIME allowlist, randomized stored filenames outside the webroot
or with an .htaccess deny), use prepared statements, and add CSRF tokens to
all state-changing forms.

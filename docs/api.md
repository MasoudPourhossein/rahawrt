# API v1

Router base: `/cgi-bin/rahawrt/wrt/api/v1/`. The development backend also accepts
`/wrt/api/v1/`. Static panel: `/wrt/` through the existing uhttpd server.

## Authentication and access

Use HTTPS on the router. The CGI transport rejects protected API requests over
HTTP; only anonymous captive discovery is available before secure login. Configure
a trusted certificate for the chosen portal hostname. Local development is bound
to loopback and can use HTTP. The backend cannot bind a public address through CLI.

Bodies are JSON objects, maximum 64 KiB. Writes require `Content-Type:
application/json`. The direct development backend requires
`X-RahaWRT-Request: 1`. Through uhttpd CGI also send
`X-HTTP-Method-Override: POST` (or `PUT`, matching the actual method). uhttpd
forwards only selected headers; CGI maps this CORS-unsafe marker to the backend
request header and never changes the HTTP method. The panel sends both markers.
No CORS is enabled. CGI emits a complete HTTP status reason phrase, so rejected
requests retain their actual 4xx/5xx status through uhttpd. Login returns an
opaque bearer token and an HttpOnly/SameSite=Strict cookie (Secure on router HTTPS).
Sessions expire after one hour and are hashed in SQLite, source-IP-bound and
revocable. Reauthentication rotates the same account/IP session. User passwords
require 12–256 characters and use salted PBKDF2-HMAC-SHA256/250000 iterations.
Login is limited to 10 attempts per IP/minute; HTTP/DNS concurrency is bounded.

Roles: admin manages configuration/security; operator reads observations and can
run read-only diagnostics; accounting issues accounts/vouchers and records
receipts; user reads only its own status/history/reports and logs out.
API keys have only their declared scopes, 60 requests/minute, explicit expiry and
immediate revocation. Keys cannot create keys, change plans/network configuration
or modify administrator accounts. All API key transport must use HTTPS.

| Method | Path | Access | Result |
| --- | --- | --- | --- |
| POST | login | anonymous | `{name,password}` → role/token/cookie |
| POST | logout | session | Revoke token and close its user gate on next tick |
| GET | me | authenticated | Identity and own account allowance/usage/expiry |
| GET | captive | anonymous | RFC captive state, portal URL, remaining bytes when online |
| GET | status | admin/operator | Preview/enforce, applied/error, timezone, compiled plan |
| GET | resources | admin/operator | Memory/load/uptime/storage/authenticated devices |
| GET | clients | admin/operator | DHCP leases, not proof of online status |
| GET | nodes | admin/operator | PassWall2 node IDs plus direct/default |
| GET/PUT | devices | staff read/admin write | Stored policy and per-device usage/upsert |
| POST | reservations | admin, enforce | `{device}` → DHCP change requiring confirmation |
| POST | diagnostics | admin/operator | `{device,target}` → router DNS/FIB observations |
| GET/PUT | plans | staff read/admin write | Plan inventory/upsert |
| POST | issue | admin/accounting or accounts:issue | Invoice-idempotent account issuance |
| POST | vouchers | admin/accounting or accounts:issue | Frozen, replay-safe batch issuance |
| GET | accounts | staff or usage:read | No passwords/hashes/keys returned |
| POST | accounts | admin | Legacy explicit account creation/replacement |
| POST | account-action | admin or accounts:manage | User lifecycle operations |
| POST | api-keys | admin | Issue key; raw token returned once |
| POST | api-keys/revoke | admin | `{id}`; immediate revocation |
| GET | reports | staff, usage:read, or own user | daily/monthly UTC JSON or CSV |
| GET | sessions | staff, usage:read, or own user | Recent session metadata, no token hashes |
| GET | audit | admin | Last 200 operation metadata entries |
| POST | receipts | admin/accounting or receipts:write | Idempotent financial receipt recording |
| GET | receipts | admin/operator | Last 100 receipts |
| GET/PUT | parental | admin | Profile inventory/upsert |
| POST | parental/refresh | admin | `{category:"adult",sha256?:...}` |
| GET | parental/sources | admin | Cached source, attribution, full license, digest/date/count |
| POST | guest | admin, enforce | New guest network; confirmation required |
| GET/POST | tunnels | admin/operator read/admin enforce write | Native interface inventory/provisioning |
| POST | tunnels/action | admin, enforce | `{id,action:"up"|"down"}`; confirmed interfaces only |
| GET | changes | admin | Pending/change status, never snapshots or confirmation secrets |
| POST | changes/confirm | admin | `{id,token}` before deadline, after apply completes |
| POST | changes/rollback | admin | `{id}`; restore prior UCI and restart services |
| GET | backup | admin, HTTPS | Sensitive bounded ZIP; offline restoration only |

`staff` means admin/operator/accounting for billing records; network/device reads
remain admin/operator only. A successful policy save is not proof of activation:
inspect `status.applied` and `status.error`. Runtime tick interval is five seconds.

## Device policy and schedules

```json
{
  "id":"phone_1", "name":"Phone", "ip":"192.168.1.20", "mac":"02:11:22:33:44:55",
  "node":"existing_passwall2_node_id", "vpn_failure":"block",
  "upload_kbps":1024, "download_kbps":4096, "quota_bytes":1073741824,
  "internet":[{"days":[0,1,2,3,4,5,6],"start":"08:00","end":"23:00"}],
  "vpn":[{"days":[0,1,2,3,4,5,6],"start":"22:00","end":"02:00"}],
  "blocked_ips":["203.0.113.0/24"], "parental_profile":null,
  "hotspot":false, "enabled":true
}
```

Days: Monday=0 through Sunday=6. Windows are start-inclusive/end-exclusive; empty
means always allowed. Overnight windows continue into the following day. Internet
permission takes precedence over VPN windows. Outside VPN windows routing is
direct. `default` selects PassWall2's global node. On the router startup loads the
OpenWrt POSIX timezone; restart after changing it, or use CLI `--timezone`.

VPN-only `block` requires a concrete remote node; special shunt/balancer/interface
protocols are refused even outside the current VPN window, because their internal
routing may intentionally send traffic directly. The global selection is resolved
and rechecked. A policy-worker error immediately attempts the independent guard.
VPN-only `block` drops ordinary forwarded bypass and blocks ordinary router DNS
unless the parental DNS proxy captures it. `direct` permits forwarding where
PassWall2 bypasses traffic; it is not health-driven failover. DHCP changes for a
known MAC retain the policy and revoke its sessions. Reservations refuse ambiguous
existing settings. Unregistered LAN identities are outside device policies;
configured guest subnets instead deny unknown identities by default.
DHCP client records include `neighbor_state` and `observed_interface` from the
IPv4 neighbor table when available. A matching reachable neighbor is a recent
observation; STALE/static/no-entry states do not prove current client presence.
A different observed MAC is reported explicitly instead of silently trusted.

## Plans, invoices and vouchers

PUT `plans` (zero quota/rate/validity/online duration means unlimited):

```json
{"id":"day","name":"One day","quota_bytes":1073741824,"upload_kbps":1024,"download_kbps":4096,"valid_seconds":86400,"online_seconds":14400,"max_devices":2,"max_sessions":2,"node":"default","quota_action":"block","reduced_upload_kbps":0,"reduced_download_kbps":0}
```

`quota_action:"throttle"` requires both reduced rates. Account speed budgets and
usage quotas are shared across bound devices, in addition to any tighter device
limit. `max_sessions` counts authenticated login sessions, not TCP/UDP flows.
Native connection-count enforcement is not implemented. Plans are snapshotted on
issuance; later edits do not silently change existing accounts.

POST `issue`:

```json
{"invoice_id":"register1_invoice1001","plan_id":"day"}
```

Optional `username` and `password` permit caller-chosen credentials. New credentials
are returned only on creation. Generated passwords are never stored in plaintext.
An exact retry returns the existing username and `password:null`; a changed
request with the same invoice ID is rejected. Concurrent retries create one
account. If the print response was lost, use `password-reset` and print the new
password; this revokes the old credential and sessions without duplicating users.

POST `vouchers`: `{"batch_id":"desk_100","plan_id":"day","count":10}`.
Count is 1–50. Batch count/plan/snapshot are fixed on first submission. Retries
never duplicate users; passwords already returned are not recoverable. Partial
batch failure can be retried safely, but it is not an all-or-nothing batch.
The panel prints one-time credentials and can clear them from its DOM. It does
not save credentials in browser storage.

POST `account-action`: `name` plus `action`:

- `suspend`, `activate`, `disconnect`, `delete`: affect user accounts only.
- `renew`: requires `plan_id` and a new `invoice_id`; grants a fresh plan/usage
  baseline and validity from now. Retry of the same renewal does not reset usage.
- `password-reset`: optional new `password`, otherwise generates one returned once.
- `unbind`: requires `device`; frees a slot. All account sessions are revoked.

All lifecycle operations revoke existing sessions. Deleted account bindings remain
closed until reassignment; accounting/history is retained. Suspended/deleted users
cannot authenticate. Exhausted/expired active users can still sign in to inspect
allowance but do not regain Internet access. Guest/voucher login requires a known
hotspot device and enforces the account's device/session limits.

POST `api-keys`: `{"scopes":["accounts:issue","usage:read"],"ttl_seconds":86400}`.
Available scopes: `accounts:issue`, `accounts:manage`, `usage:read`, `receipts:write`.
Send returned token as `Authorization: Bearer ...`. No raw key is listed later.

POST `receipts`:

```json
{"id":"invoice1001","account":"rw_existing_user","amount_minor":10000,"currency":"IRR","reference":"cash-register-1"}
```

Receipts are financial records; they do not independently grant access or process
payments. Exact retries are idempotent. Reports: `reports?period=monthly` or
`reports?period=daily&format=csv`. Usage and report dates are UTC, independent of
policy timezone. Audit stores actor/action/subject/time, never request bodies.

## Guest, parental, native tunnels and recovery

POST `guest` example:

```json
{"address":"192.168.50.1/24","radio":"radio0","ssid":"RahaWRT Guest","password":"supply-a-private-wifi-password","open_wifi":false,"portal_host":"portal.your-owned-domain.example"}
```

Use the first usable gateway in a non-overlapping RFC1918 /24–/28. Omitting radio
creates a bridge only. WPA2 is default; open Wi-Fi requires explicit selection and
is not encrypted by the login page. A trusted uhttpd certificate for `portal_host`
is required for reliable OS captive discovery. Gateway IP is the default hostname;
self-signed certificates may prevent OS discovery. A temporary default-deny guard
precedes network activation. DHCP leases enroll unknown guest MACs as gated devices.
Guest-to-LAN forwarding and zone input are rejected except DHCP, policy DNS,
HTTPS 8443 and HTTP discovery 2080. Guest uhttpd has an independent docroot with
only RahaWRT assets/CGI and an explicit independent server config (no inherited
`/etc/httpd.conf` authentication/handlers), reuses the main instance's certificate/key paths and
exposes no LuCI/ubus CGI. Admin/operator/accounting credentials and API keys are
refused from guest source addresses. Wi-Fi AP isolation is requested from the
driver and still requires hardware testing. Unauthenticated TCP/80 is redirected
to a bounded discovery listener that returns the configured HTTPS portal URL;
credentials are never accepted over HTTP. Cached forwarded/proxy HTTP paths are
gated too. DHCP 114 and manual login use `https://HOST:8443/wrt/`.
Guest/hotspot DNS goes through the policy listener: closed accounts can resolve
the local portal, but cannot forward upstream queries. A small fixed set of OS
connectivity-probe names gets a zero-TTL gateway answer while closed, allowing
legacy HTTP detection to reach the portal. These answers never contact upstream
DNS; normal resolution resumes after login. Other domains remain refused.

Parental profile example:

```json
{"id":"child","allow":["allowed.example"],"block":["blocked.example"],"categories":[],"safe_search":true,"block_encrypted_dns":true}
```

Assign its ID to a device. Allow entries take precedence and include subdomains.
Refresh `adult` before enabling that category. The list's GPL license/attribution
is retained with its source and digest; a supplied SHA-256 pin is enforced.
Direct-mode captured DNS uses a private TCP worker and the configured upstream
(default 1.1.1.1:53). It verifies the first unconditional GID 9912 return in both
PassWall2 output chains before spawning, so the router global node cannot silently
replace the selected direct path. Unsupported bypass contracts fail closed. This is
not a validating recursive DNSSEC resolver. Selected Google/Bing/YouTube names get
SafeSearch CNAME/address answers. DoT/DoQ port 853 and several known DoH names can
be blocked; arbitrary encrypted DNS/content bypass is not claimed impossible.
VPN-only DNS uses a private loopback SOCKS helper for the selected concrete
Xray/sing-box node, including the current concrete global node. Shunt/balancer
nodes are refused for strict DNS. Native-tunnel DNS uses an owned SO_MARK route,
binds the observed interface and verifies PassWall2's GID 9912 output exemption
before running its private worker. Failure returns SERVFAIL unless `vpn_failure`
explicitly permits direct fallback. Real SOCKS test peers and a separate native
DNS namespace were tested; actual PassWall2/core/router integration remains a
hardware acceptance gate.

Devices and plans can set `tunnel:"rv_ID"` for a confirmed native tunnel, with
`node:"direct"`; these selectors are mutually exclusive. Owned per-source and
marked-DNS RPDB rules use protocol 242 and collision-free tables. The terminal
unreachable route prevents a down strict tunnel from falling through to WAN.
Interface `up` is an observation, not an end-to-end health certificate.

Native tunnel examples are in `docs/development.md`. Provisioning returns a
change ID and a one-time confirmation token. Inspect `changes`; after reconnecting
and testing, confirm before three minutes or it rolls back. Restart recovers
pending changes by rollback. These confirmations apply to guest/reservation/tunnel
UCI changes, not a universal management-loss watchdog for every policy update.

Errors: 400 invalid input/conflict, 401 missing session/key, 403 role/scope/HTTPS
restriction, 404 unknown endpoint, 429 throttled, 502 category fetch failure,
503 unavailable PassWall2/CGI service. Unexpected router command failures are
reported without echoing credential-bearing command arguments.

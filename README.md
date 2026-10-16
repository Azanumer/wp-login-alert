# WP Login Alert

Early warning for compromised WordPress accounts: every time a monitored role
(administrators by default) logs in, you get an email with the IP, reverse DNS,
browser, and time — flagged **NEW IP** when that address has never been seen
for the account. Every successful login is also kept in a paged log under
**Tools → Login Log** (90-day retention, pruned by a daily cron).

## How it works

1. On `wp_login`, the login is written to a custom table (`wp_wla_logins`).
2. If the user's role is monitored, the IP is checked against their known-IP
   list (stored as user meta, expires after 90 days).
3. A new IP triggers an email like `[My Site] NEW IP login: admin` with full
   details; repeat IPs still send a quieter `[My Site] Login alert: admin`.

## Settings (Settings → Login Alert)

- **Monitored roles** — which roles trigger alerts (default: administrator).
- **Alert email** — empty = site admin email.
- **Known IP lifetime** — days before an IP is "forgotten" (default 90).
- **Login log retention** — days of history kept (default 90).

## Behind a proxy / Cloudflare

The client IP defaults to `REMOTE_ADDR`. If your server sits behind a trusted
proxy, override it:

```php
add_filter( 'wla_client_ip', function () {
    return $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'];
} );
```

Only do this when you actually trust the proxy — otherwise the header is
attacker-controlled.

## Install

Upload the folder to `wp-content/plugins/`, activate, visit
**Settings → Login Alert**. Deleting the plugin (not just deactivating) drops
the log table, the option, and all known-IP data.

MIT licensed.

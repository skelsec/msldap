# msldap test suite

A staged, opt-in pytest suite for `msldap`. The default invocation runs only
**offline** tests (no network, no lab) and is always safe for CI. Tests that
talk to a real Active Directory / LDAP server are **opt-in** behind CLI flags.

## Layout

```
tests/
├── conftest.py            # collection policy + --run-* opt-in gates (no fixtures)
├── known_failures.yml     # registry of confirmed msldap defects (KF-XXXX)
├── test.sh                # convenience runner (offline / live / destructive / all)
├── support/               # import-safe helpers (no network on import)
│   ├── builders.py        # synthetic LDAP entry builders
│   ├── agen.py            # helpers to drain (result, err) async generators
│   └── known_failures.py  # xfail helper backed by known_failures.yml
├── unit/                  # deterministic, offline unit tests
├── interop/live/         # live AD-target tests (opt-in)
│   ├── _lab.py           # profile loading, reachability, logged_in context mgrs
│   ├── conftest.py       # live fixtures (client / connection / root / essos / gc)
│   ├── test_adcs.py      # ADCS/PKI enumeration (forest root)
│   ├── test_forest.py    # Global Catalog, trusts, gMSA, cross-domain SIDs
│   └── profile.example.yml
└── interop/openldap/     # non-AD (OpenLDAP) interop tests (opt-in, dockerized)
    ├── docker-compose.yml # disposable OpenLDAP server (base dc=example,dc=org)
    ├── seed.ldif          # sample OUs / users / group
    ├── conftest.py        # self-skipping OpenLDAP client fixture
    └── test_openldap.py   # base-DN discovery, paged search, whoami regressions
```

## Install

```bash
pip install -r requirements-test.txt
pip install -e .          # msldap itself
```

## Running

```bash
# Offline only (default) + coverage
pytest tests/unit --cov=msldap --cov-report=term-missing
# or:
tests/test.sh offline

# Everything offline + against a live target
pytest tests --run-live
tests/test.sh live

# Include create/modify/delete tests (DISPOSABLE LAB ONLY)
pytest tests --run-live --run-destructive
tests/test.sh destructive

# Include slow tests (full BloodHound collection)
tests/test.sh all
```

### Opt-in flags

| Flag                 | Enables                                                        |
|----------------------|---------------------------------------------------------------|
| `--run-live`         | tests marked `live` (need a reachable, configured target)     |
| `--run-destructive`  | tests marked `destructive` (create/modify/delete). Implies `--run-live` |
| `--run-slow`         | tests marked `slow` (e.g. full BloodHound dump)               |

If the configured target is unreachable, live tests **skip** (not fail).

### Non-AD interop (OpenLDAP)

`msldap` is AD-focused but must still connect to plain LDAP servers. The
`interop/openldap` suite covers that path against a disposable, dockerized
OpenLDAP (base DN `dc=example,dc=org`). It is gated behind `--run-live` and
skips cleanly when the server is not up.

```bash
docker compose -f tests/interop/openldap/docker-compose.yml up -d
pytest tests/interop/openldap --run-live
docker compose -f tests/interop/openldap/docker-compose.yml down -v
```

Point it elsewhere with `$MSLDAP_OPENLDAP_URL` (full msldap URL) or
`$MSLDAP_OPENLDAP_HOST` / `$MSLDAP_OPENLDAP_PORT`.

## Configuring a live target

Copy the example profile and edit it (or point `$MSLDAP_TEST_PROFILE` at your own):

```bash
cp tests/interop/live/profile.example.yml tests/interop/live/profile.local.yml
```

`profile.local.yml` is git-ignored. Credentials may be inlined for a throwaway
lab, or supplied via environment variables so nothing is committed:

```bash
export MSLDAP_TEST_HOST=192.168.56.11
export MSLDAP_TEST_DOMAIN=NORTH
export MSLDAP_TEST_USERNAME=vagrant
export MSLDAP_TEST_PASSWORD=vagrant
pytest tests --run-live
```

> Password-write operations (`add_computer`, `create_user_dn`) require a
> confidential channel. Use `protocol: ldaps` or add `params: {encrypt: 1}` in
> the profile; otherwise those destructive tests skip with a clear message.

### Multiple targets (whole-lab tests)

Some tests need more than the primary DC: the **forest root** (its Configuration
partition holds the ADCS/PKI objects — see `KF-0007`), a **second forest** for
cross-forest trust/SID resolution, and the **Global Catalog**. Declare the other
DCs under `extra_targets` in the profile (they reuse the same account by
default):

```yaml
extra_targets:
  root:                 # forest root, e.g. sevenkingdoms.local
    host: 192.168.56.10
    domain: SEVENKINGDOMS
    protocol: ldaps
  essos:                # a second, trusted forest
    host: 192.168.56.12
    domain: ESSOS
    protocol: ldaps
```

The `root_client`, `essos_client` and `gc_client` fixtures skip cleanly when the
corresponding target is not configured or not reachable, so the suite still runs
against a single DC.

## Known failures

`known_failures.yml` catalogs confirmed bugs found while writing the suite. Each
is asserted with a **strict** `xfail`, so if a bug gets fixed its test starts
XPASSing and the suite fails — a reminder to retire the registry entry.

Current entries (see the file for full details):

| ID | Area | One-liner |
|----|------|-----------|
| `KF-0003` | `commons.keycredential.KeyCredential.from_pfx_data` | Reconstruct from PFX crashes in the constructor (`struct.error`). |
| `KF-0004` | `commons.ldif.MSLDAPLdiff.parse_entry` | Base64 (`attr:: …`) values are never detected/decoded. |
| `KF-0005` | `commons.ldif.MSLDAPLdiff.build_index` | `UnboundLocalError` on the first `dn:` line — LDIF parsing is dead. |
| `KF-0006` | `connection.MSLDAPClientConnection.get_extra_info` | Error handler calls `traceback.print_exc()` without importing `traceback` → `NameError` masks the real error (breaks `simple`/`plain`/`anonymous` `test_connection`). |
| `KF-0007` | `client.MSLDAPClient.list_certificate_templates` (& sibling ADCS/CA enumerators) | Build the search base from `defaultNamingContext` instead of the forest-wide `configurationNamingContext`; on a child-domain DC this raises `noSuchObject`. |

`KF-0006` has a deterministic offline `xfail` in `tests/unit/test_connection_offline.py`.
`KF-0007` is environment-dependent (only reproduces from a non-root DC), so the
two live ADCS tests skip with a clear `KF-0007` message rather than failing.

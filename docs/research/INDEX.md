# Research spikes — index

Question → evidence map. Each heading gives the stable spike name used by
citations elsewhere in the repository and the archive that holds its evidence.

The archives are deliberately not rendered or indexed as Markdown. They contain
experiment logs, intermediate reasoning, and preliminary interpretations; they
are evidence, not normative project claims. Prefer `DESIGN.md` and the synthesis
documents below for conclusions.

- Read only the pointed range with
  `docs/research/read-result <archive.zst> <first-line> <last-line>`. Do not
  search or decompress a whole result archive.
- Ranges point at the section that answers the question, not just its heading.
- Per-spike work orders were removed once every result landed — git history up
  to commit `be2486e`.

Meta docs, read once:

- [`../../DESIGN.md`](../../DESIGN.md) — what was *concluded*; every
  decision here is already folded into it. This index is what was *observed*.
- [`../windows-kerberos-findings.md`](../windows-kerberos-findings.md)
  — cross-topic narrative from spikes 2, 3, 5, 5b (§ list at the bottom of this
  index). Prefer it for prose; prefer the result files for exact
  commands/evidence/line-cited claims.
- [`../../testbench/`](../../testbench/) — the fixture corpora these spikes
  produced, plus the live-tenant tooling and the capture decoder that have no
  equivalent in `crates/`.

## 1. Samba TGT issuance — spike `samba-tgt-issuance`

Archive: `samba-tgt-issuance.zst`.

- Q1 Can `exportkeytab --principal` export an ordinary user? → :136-138
- Q2 Does export preserve keys/kvno? → :139-142
- Q3 Which principal spelling works? → :143-151
- Q4 Which enctypes are exported/accepted? → :152-160
- Q5 Does `kinit -k -r` get a renewable TGT? → :161-162
- Q6 Which settings cap lifetimes? → :163-164
- Q7 Are ineligible users (disabled/expired/locked) rejected? → :165-172
- Q8 Is export safe under concurrency? → :173-176
- Q9 What local permissions does export require? → :177-181
- Q10 Can a SID resolve to the current principal safely? → :182-187
- Pinned baseline (image, Samba/krb5 versions, functional level) → :15-48
- Security analysis (brute-force, key material, injection risk) → :316-377
- Decision (GO) → :378-396
- Downstream hand-offs (feeds attribute/network/runtime/renewal spikes) → :397-414

Conditional PKINIT-fallback spike **not run** — local key export got GO, so that
branch was skipped (Decision, :378-396).

## 2. Entra token validation — spike `entra-token-validation`

Archive: `entra-token-validation.zst`.

Each numbered question has its own subheading in the result.

- Q1 Token version / manifest control (v2.0 selected) → :57-85
- Q2 Exact `iss`/`aud` forms → :86-100
- Q3 Authorized-client (`azp`) claim → :101-113
- Q4 Delegated scope vs app-only roles → :114-148
- Q5 Tenant and stable user identity (`tid`+`oid`) → :149-170
- Q6 Member vs guest claim differences → :171-207
- Q7 Guest policy → :208-224
- Q8 Signing algorithms/key types → :225-240
- Q9 JWKS caching, unknown `kid`, rollover, outage → :241-291
- Q10 Clock skew → :292-301
- Q11 `xms_cc`/auth-context/MFA/CA — deferred → :302-317
- Q12 Errors returned to `winhelper` → :318-335
- Decisions at a glance → :24-54
- App-registration recipe (broker + public client + portal walkthrough) → :337-613
- Locked validation policy (normative, what the verifier must enforce) → :632-672
- Live-tenant verification (real token capture, app-only reject, guest claims,
  key rollover, consent prompt, `idtyp` emission) → :761-811
- **Security-relevant note**: app-only tokens with `aud=broker` are issued to
  ANY confidential client in the tenant — `scp` presence + `idtyp!=app` are the
  actual access control, not defense-in-depth →
  [`DESIGN.md`](../../DESIGN.md) § Entra validation (last bullet)

## 3. Samba AD identity attribute — spike `samba-ad-identity-attribute`

Archive: `samba-ad-identity-attribute.zst`.

- Decisions at a glance (attribute, encoding, example value, filter, role
  marker, delegation, uniqueness) → :12-23
- Schema/version baseline → :37-59
- Candidate comparison + why `msDS-ExternalDirectoryObjectId` → :60-120
- Entra Connect/Cloud Sync compatibility conflict (why not operative) → :122-169
- Rejected attributes, concrete conflicts → :170-184
- Encoding: E1 selected (pipe-delimited) vs E2 rejected → :185-239
- Exact broker LDAP filters → :240-271
- Write examples/commands → :272-308
- Duplicate-value policy (Samba enforces none → fail-closed) → :309-339
- Delegated ACL requirements (identity attr) → :340-395
- Role marker: attribute, encoding, lookup, duplicate policy → :396-441
- Lookup-performance evidence (indexed 0.1ms @ 1784 objects) → :442-467
- Tool-preservation across normal edits → :468-486
- Experiment index (all 12, evidence file map) → :487-511
- Hand-offs / SERVER-PLAN reconciliation → :530-551

## 4. Entra directory sync — spike `entra-directory-sync`

Archive: `entra-directory-sync.zst`.

- Q1 Graph permissions → :70-111
- Q2 Gate by name once then immutable id; rename+cursor-loss recovery → :243-255, :664-678
- Q3 Direct vs transitive admission → :271-284
- Q4 Nested representation → :271-284, :580-662
- Q5 Group-selection model → :256-270
- Q6 Delta endpoints → :112-242
- Q7 Pagination/throttling/retry/invalidation → :112-242
- Q8 Complete vs partial read detection → :341-357, :897-916
- Q9 Naming (allocation, UPNs, collision errors) → :474-543
- Q10 All ops via delegated LDAPS → :397-473
- Q11 Minimal ACL (16 ACEs) → :397-473
- Q12 Collision policy → :509-543
- Q13 Entra object/group eligibility table → :285-340
- Q14 Broker effective-membership query (role marker + matching-rule-in-chain) → :580-662
- Q15 Password age/rotation (`DONT_EXPIRE_PASSWD` mandatory) → :544-579
- Lifecycle state machine (ACTIVE→DISABLED→RETIRED→delete; group quarantine) → :724-778
- Live-tenant verification: closed (6/9) → :918-928; **still open** (410
  `Location` shape, real throttling values, delta-lag bound) → :929-937
- Hand-offs / SERVER-PLAN reconciliation → :962-997

## 5. Host networking & DNS — spike `host-networking-and-dns`

Archive: `host-networking-and-dns.zst`.

- Platform constraint (macOS dev vs Linux-VM target — read first) → :7-25
- Q1 Ports bound during provision/join/admin → :102-144
- Q2 Dynamic RPC range reducible → :158-176
- Q3 Host service conflicts (resolved-stub, nmbd, krb5-kdc, slapd, 80/443) → :54-101
- Q4 Required host config (hosts file, resolv.conf, chrony+ntpsigndsocket) → :54-101
- Q5 Single-address advertisement → :145-157
- Q6 Delegation model (conditional forwarding, not NS delegation) → :282-340
- Q7 Records per client class (SRV/A/reverse) → :282-340
- Q8 DNS-01 under split-horizon → :341-412
- Q9 Caddy DNS plugin/secret format → :341-412
- Q10 Firewall matrix (nftables, proven) → :223-281
- Q11 Outbound dependency matrix (Graph/OIDC/etc.) → :481-497
- Q12 Public records under split-horizon → :282-340
- Decision: CONDITIONAL GO → :432-452
- **Requires Linux-VM follow-up** (bounded list, condition not open risk) → :453-480

## 6. Container runtime boundaries — spike `container-runtime-boundaries`

Archive: `container-runtime-boundaries.zst`.

- Q1 Truly static binaries (rustls/ldap3/reqwest)? → :21-84
- Q2 CA-root supply/update (public + private/SAN) → :101-149
- Q3 Unix socket via named volume reliable? → :150-196
- Q4 UID/GID so only broker connects → :150-196
- Q5 Stale sockets across restart/down-up → :150-196
- Q6 Supervision (docker-init + `wait -n`, Samba self-heals) → :204-236
- Q7 Writable/persistent/tmpfs paths per container → :298-330
- Q8 Loopback bind without extra caps → :237-297
- Q9 Caddy reaches loopback listener → :331-356
- Q10 Hardening that works vs breaks Samba (cap matrix) → :237-297
- Realm capability matrix (provisioning vs steady state vs broker/sync/caddy) → :239-297
- Downstream hand-offs (SAN cert, socket contract, cap set) → :450-464

## 7. Joined NAS authorization — spike `joined-nas-authorization`

Archive: `joined-nas-authorization.zst`.

- Q1 Minimal supported member config (smbd-only, no nmbd) → :49-98
- Q2 `idmap_rid` settings for stable cross-member IDs → :147-183, :322-410
- Q3 Reserved ranges (`*`→tdb 100000-199999, domain→rid 1000000-1999999) → :147-183
- Q4 Winbind nesting expansion (global→domain-local) → :227-266
- Q5 ID stability across reboot/leave-rejoin/cache-flush → :322-410
- Q6 Rename effects on IDs/ACLs (name-based `valid users` breaks) → :340-387
- Q7 Disabled-user behavior (AS+TGS denied immediately) → :411-427
- Q8 Membership removal — **four-layer revocation matrix** (acceptance-critical) → :267-321
- Q9 Observed network connections (join + steady state) → :428-454
- Q10 Member/DC version compatibility → :17-48
- Operator-facing member join recipe (copy-paste) → :99-146
- Surprises / operational notes → :470-497

## 8. Windows TGT renewal (unjoined client) — spike `windows-tgt-renewal`

Archive: `windows-tgt-renewal.zst`.

- Two defects found before the matrix could run: UDP fragmentation drop → :110-195;
  redirector NTLM fallback → :159-195
- Ticket shape as injected (`klist` fields) → :196-220
- Q1 Does Windows auto-renew an injected TGT? **No, never.** → :223-260
- Q2 When does it renew relative to expiry? (doesn't; mechanism corrected in
  research spike `windows-tgt-followup-entra-joined`) → :223-260; correction at
  lines 690-736 of that spike
- Q3 Renewal/access while broker+issuer unavailable → :355-369
- Q4 New CIFS/HTTP tickets from the injected TGT → :196-220, :223-260
- Q5 Cache metadata via `klist` before/after → :196-220, :459-488
- Q6 Samba user disabled after injection → :261-285
- Q7 Entra user disabled but sync not run — not directly testable here (Samba-only
  spike); recorded limitation → :607-624
- Q8 Samba user disabled by sync → :261-285 (same mechanism as Q6)
- Q9 Samba key rotated → :286-299 (no effect at any layer)
- Q10 Group membership / NAS ACL changes while tickets exist → :300-354
- Q11 Realm-scoped purge reliability → :424-441
- Q12 Unjoined vs Entra-joined differences — **not measured** (platform gap) →
  mandatory follow-up spike, section 9 below
- Four cache layers, Windows vs Linux baseline → :458-489
- Revocation levers ranked by measured speed → :490-509
- Is Windows SSP auto-renew safe to rely on? **No** → :510-568
- Recommended default lifetimes (10h/7d justification) → :569-589

## 9. Windows TGT follow-up, Entra-joined client — spike `windows-tgt-followup-entra-joined`

Archive: `windows-tgt-followup-entra-joined.zst`.

- Q1 Does injection work at all under Credential Guard/VBS? **WORKS** → :177-189
- Q2 Coexistence with the session's existing PRT/ticket? **PRIMARY; coexists** → :190-217
- Q3 Does SPNEGO select the injected ticket? **YES, CLOSED** → :190-217 (evidence),
  :1084-1130 (closure statement)
- Q4 Does the NTLM fallback reproduce, same recovery cost? → :737-793
- Q5 Does Windows still never renew (mechanism)? **Renews at T-15m, never installs
  the result — re-injection conclusion stands** → :690-736
- Q6 Native transport without the loopback relay → :493-689 (root cause: PAC
  exceeds UDP reply size, `KRB-ERROR 52`, stateful firewall drops fragments)
- Q7 Row-4 cached-CIFS-ticket behavior on a joined box → :897-952 (DIFFERENT/better
  than phase 5 — no availability defect)
- Q8 Realm-scoped purge / what "sign out" must do (**purge ≠ sign-out**) → :794-827
- Q9 Broker vs issuer separately stoppable, do rows 2/3 differ? → :879-896
- Account disable, all four cache layers (byte-identical to phase 5) → :953-1019
- Group removal ladder (byte-for-byte reproduction) → :1020-1087
- Procedural traps: `ACCESS_DENIED` meaningless without session id → :1088-1127;
  open SMB session masks Kerberos tests → :1128-1140
- Per-finding comparison table vs unjoined phase 5 (SAME/DIFFERENT/NEW) → :1141-1168
- Tray-design requirement deltas → :1169-1225
- Gap status (what's closed, what's carried forward: Q2/Q3 on cloud-trust
  tenants, rung 1.5) → :1226-1272
- Teardown + acceptance criterion 5 (workstation fully restored) → :1273-1365

## 10. WAM / WHfB silent broker-token acquisition — spike `windows-wam-whfb-silent-token`

Archive: `windows-wam-whfb-silent-token.zst`.

Question: can Windows silently (no browser) mint a broker-API token via WAM/WHfB
against the existing public client, and does that token pass the broker's validator?

- Measured on a physical Entra-joined box, from WSL2.
- The device's home tenant differs from the app tenant (operator is a B2B
  guest) — read every result through that cross-tenant lens.

- Placeholder legend + the cross-tenant split (device vs app tenant) → :15-33
- Preconditions (PRT present, values from broker `/config`) → :45-54
- Q1 Silent on a cold cache? **No — AADSTS50076, CA MFA on the broker resource** → :68-83
- Q2 Broker redirect URI mandatory (`ms-appx-web://…/<client-id>`) → :84-94
- Q3 After one interactive MFA bootstrap, next call is silent (no prompt) → :95-103
- Q4 Survives reboot + forced fresh mint, both promptless → :104-129
- Q5 Token shape vs browser / locked policy (passes; no `xms_cc`/CA/device claims) → :130-184
- Q6 End to end — broker minted a TGT from the WAM token → :185-203
- Decision: **GO**, qualified only by the one-time bootstrap; home-tenant hosting
  may remove even that → :204-241
- Recommended `acquire_token` wiring (`agent.rs:705-716`, `experimental_wam`) → :215-235

Practical closure of research spike `entra-token-validation` §11
(`xms_cc`/CA/MFA) — the WAM token carries no such claims. **Answered here; do
not edit that spike's archive.**

## 11. ADUC, elevation and injected tickets — spike `aduc-elevation-and-injected-tickets`

Archive: `aduc-elevation-and-injected-tickets.zst`.

Not work-ordered. Began as "make ADUC work against the bench"; kept for one
finding — an injected TGT is a fully working LDAP credential, and ADUC still
cannot use it. Measured 2026-07-25, live bench, one non-joined client.

- Bench, date, and what was not bisected → :7-15
- Q1 Can the injected TGT drive ADUC? **No; and the DC logs nothing at all** → :19-34
- Q2 Does it authenticate LDAP? **Yes — `S.DS.P` and `[ADSI]` both bind** → :35-46
- Q3 Where is the barrier? **Elevation — separate LUID, separate ticket cache** → :47-80
- Q4 Why `cmdkey` works and `runas /netonly` does not → :81-95
- Q5 Does granting `Administrators` help? **No — failure is authentication-side** → :96-103
- Q6 Is Samba's own zone locator-complete? **Yes, but with bridge addresses** → :104-138
- Q7 Which locator record does ADUC need? **`_ldap._tcp.<domain>`, for Change Domain** → :139-149
- Q8 Why the startup "Naming information cannot be located" notice → :150-160
- Q9 Why "Access is denied" after a successful bind (`:445` collision) → :161-187
- Open: standard-user MMC, no elevation, no stored credential → :189-199
- Implication: a KerBridge admin GUI should speak LDAP, not lean on ADUC → :203-212

Operator procedure distilled from this:
[`../rsat-and-kerbridge-management.md`](../rsat-and-kerbridge-management.md).
This file is only the evidence.

## 12. Unicode names — spike `unicode-name`

Archive: `unicode-name.zst`.

Not work-ordered. "Can a user whose name is not ASCII sign in?" Measured across
both halves 2026-07-28/29, live bench plus a Windows 11 client. The answer is
yes everywhere below KerBridge, and the only obstacle was our own two copies of
the naming rule disagreeing with each other.

- Which bench each measurement came from — CI vs live, they differ → :7-14
- Verdict, and why a real Windows DC is out of scope not a gap → :16-36
- Linux half: per-name table, with what was and was not run per bench → :38-64
- `ldbsearch` base64, and why the issuer sees the right bytes at all → :70-74
- Q Does the Windows LSA accept a non-ASCII client principal? **Yes** → :81-102
- Q Does the SMB redirector use it, or fall back to NTLM? **Uses it; `cifs/` TGS** → :92-102
- Two traps that fake a failure (no file server; stale SMB session) → :104-116
- Q Do NFC and NFD behave the same? **No — and it decided the fix** → :118-139
- Q Does `is_alphanumeric()` cover non-Latin marks? **Yes, except Latin NFD** → :125-132
- Entra sync: what a Unicode name mints, and what does not follow a rename → :141-158
- What changed in the code, and why the dependency lives only in sync → :160-177
- Known limits: homoglyphs, group names, names NFC cannot compose → :179-186

The rule this produced is `kerbridge_core::sam`; that module's own docs are the
reference for the rule, and this file is the evidence behind it.

## 13. Device-grant TPM key — spike `device-grant-tpm-key`

Archive: `device-grant-tpm-key.zst`.

Not work-ordered. "Does `winhelper/src/device.rs` work on a real TPM?" It had
only ever been compiled, never run on one. Measured 2026-08-01 on a physical AMD
firmware TPM, unelevated.

- Which machine, which TPM, which privilege → :15-26
- Q1 Does an ordinary user create the key without elevation? **Yes, ~100 ms** → :36-54
- Q1 Where the TPM's time goes (per-call timings) → :42-50
- Q2 Does the platform provider accept an export policy of nothing? **Yes** → :56-70
- Q3 Is the public blob the 8-byte header `point_from_ecc_blob` assumes? **Yes** → :72-90
- Q3 Why `dwMagic` is still not checked → :87-90
- Q4 Is the signature 64 bytes of fixed `r || s`? **Yes** → :92-112
- Q4 The TPM-signed vector the broker's own verifier now accepts → :108-112
- Q5 Does `NCryptDeleteKey` free the handle? **Yes — a real double free** → :114-127
- Q6 Does the key survive a reboot? **Yes**, and why no logoff test → :129-143
- Q7 What every failure mode returns, with names → :145-191
- Q7 Why the provider-open failure is a raw `NTSTATUS` → :159-163
- Q7 Why machine scope fails at finalize, not create → :170-177
- Q7 A create that never finalizes leaves nothing behind → :179-185
- Q7 The four conditions this bench could not produce → :187-191
- Q8 Second machine (ARM64 vTPM) — not run → :193-196
- Decision (no change) and what is still open → :205-216

## 14. macOS ticket injection — spike `macos-ticket-injection`

Archive: `macos-ticket-injection.zst`.

Not work-ordered. The four unmeasured assumptions under "the macOS agent is a
`sys/macos.rs` plus a menu-bar shell". Measured 2026-08-02 on macOS 26.4.1 against
the live bench, unelevated throughout.

- Which machine, which Heimdal, what baseline was cleared first → :26-39
- Q1 Does discovery/OIDC/the broker exchange work off Windows? **Yes, unchanged** → :57-68
- Q2 Does Heimdal read the broker's MIT ccache? **Yes, natively — no KRB-CRED** → :70-85
- Q3 How a ccache becomes the OS credential, and the two implementation traps → :87-108
- Q3 Why the default cache name must be resolved at each use, never persisted → :98-102
- Q4 Does macOS need enrollment or elevation? **Neither** → :110-131
- Q4 The one deployment shape that would still need admin (realm ≠ DNS domain) → :126-131
- Q5 SMB from the command line, and that the principal reaches the server → :133-139
- Q6 Does Finder connect with no password? **Yes**, and how it was proven → :141-160
- Q6 That `gssd` sees a cache created outside the GUI session → :157-160
- Q7 Does an established session outlive the credential? **Yes** → :162-166
- Q8 Does macOS renew an injected TGT? **No** — nothing even asks → :168-180
- Q9 What an expired TGT does to an open mount: dropped mount, wedged I/O → :182-225
- Q9 What actually releases the wedge: a ~10 min client timeout, not re-injection → :209-225
- Q10 Does a mount cross its ticket's end time on a fresh TGT? **Yes, invisibly** → :227-256
- Q10 That injecting a TGT *erases* the cached service ticket → :246-252
- Windows vs macOS failure at expiry, side by side → :258-268
- What this settles: no helper, no `repair.rs`, no elevation, schedule proven → :270-297
- Design trap: injection must append, not reinitialize the cache → :283-290
- Open: additive injection, multi-realm cache, logout/reboot → :299-315

## Cross-topic narrative — [`windows-kerberos-findings.md`](../windows-kerberos-findings.md)

Prose synthesis; its headings are already phrased as questions.

1. Entra token validation
   - Which access-token shape was usable? → :91-155
   - Distinguish delegated users from app-only callers? → :156-168
   - Which claims identify members vs guests? → :169-180
   - Signature/key-rollover/time checks exercised? → :181-216
   - Should CA/MFA/auth-context be broker policy? → :217-228
   - What should validation failures reveal to the client? → :229-244
2. Directory synchronization: Graph → Samba
   - Which Graph permissions sufficed? → :247-278
   - Which full-read/delta behaviors can silently corrupt sync? → :279-323
   - Which objects/groups were suitable to project? → :324-337
   - How should nested admission be represented? → :338-365
   - How does the gate survive rename/cursor-loss/deletion/ambiguity? → :366-378
   - Could sync run entirely through delegated LDAPS? → :379-437
   - How should names/passwords be managed? → :438-456
   - How should deleted/disabled objects be represented? → :457-471
3. TGT injection into Windows
   - Does injection work in an Entra-joined logon session? → :474-516
   - Which logon session must perform injection? → :517-535
   - What cache shape did Windows assign? → :536-569
4. Realm registration and Kerberos transport
   - Can DNS SRV replace external-realm registration? → :572-607
   - What made transport reliable for a `ksetup` realm? → :608-694
   - Will SPNEGO select the injected realm for passwordless SMB? → :695-718
   - Which service-ticket types were proven? → :719-730
5. Ticket lifecycle and failure recovery
   - Does Windows renew a `KerbSubmitTicketMessage` TGT? → :747-774
   - Do broker/issuer availability affect cached-ticket use? → :775-791
   - What happens to SMB when the KDC is unavailable? → :792-816
   - Can Windows get stuck on NTLM after a Kerberos failure? → :817-858
   - Can a failed diagnostic alter the ticket cache? → :859-876
   - Is ticket purge sufficient for sign-out? → :926-947
6. Revocation timing and cache layers
   - How fast does disabling the account revoke access? → :963-995
   - When do group removals take effect? → :996-1034
   - Does key rotation revoke existing tickets? → :1035-1047
   - Which cache layers determine revocation/outage behavior? → :1048-1066
7. Test methodology
   - Which findings changed unjoined vs Entra-joined? → :1069-1086
   - Which observations are trustworthy? → :1087-1137
- Implementation implications (consolidated) → :1138-1160

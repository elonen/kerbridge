# DNS records and firewall

This page gives detail for
[step 3 (*Publish the DNS records*) in SETUP.md](../../SETUP.md#3-publish-the-dns-records).

- If you use `acme` or `acme-dns`, do this step **before** step 4. Without the
  records, the certificate cannot be issued, and `make up` will fail while it
  waits for the certificate.
- If you do not, you can do this step in parallel. But you must complete it
  before any client can work.

## The records

Publish these records in the zone that your **LAN clients** use for name
resolution. Do not publish them in Samba's internal DNS. The DC operates its own
DNS server for its own use, and the records there can contain addresses to which
your clients have no route. This split is intentional.

```
kerbridge.example.site            A     <broker host LAN IP>

_kerbridge._tcp.example.site      SRV   0 100 443 kerbridge.example.site.

_kerberos._udp.example.site       SRV   0 100 88  kerbridge.example.site.
_kerberos._tcp.example.site       SRV   0 100 88  kerbridge.example.site.

_ldap._tcp.example.site           SRV   0 100 389 kerbridge.example.site.
_ldap._tcp.dc._msdcs.example.site SRV   0 100 389 kerbridge.example.site.
```

- `_kerbridge._tcp` is the record that belongs to KerBridge. A client that has
  no configuration uses this record to find the broker. The user does not type a
  URL, and no registry push is necessary. The client only accepts a target
  inside the domain that it queried. If the target is outside that domain, the
  client refuses it and writes the refusal to its log.
  - **One record is sufficient for all subdomains.** A client that has the DNS
    suffix `usr.example.site` queries that zone first, and then queries the
    parent zone `example.site`. As a result, the client finds this record
    without a copy in each subdomain. The client would in fact *refuse* a copy
    in a subdomain, because the target `kerbridge.example.site` is outside the
    subdomain that answered. Publish the record one time, in the zone that
    contains the broker. The upward search stops at two labels, so it never
    reaches a bare TLD.
  - If the address is not pre-filled on a client, read
    `%APPDATA%\KerBridge\kerbridge.log`. The log shows the names that the
    client tried, and the reason that it refused an answer.
- `_kerberos._udp` is the record that Windows queries. Publish `_kerberos._tcp`
  also, because it has no cost and other clients use it.
- The two `_ldap._tcp` records are the **DC-locator** pair. The Windows
  workstation of step 7 is a foreign-realm Kerberos client and never queries
  them. These records are necessary for each tool that must find the DC *as a
  DC*: RSAT and ADUC on a machine that is not joined, and a domain member that
  resolves the realm through this zone and not through the DC.
  - These two records are not the full locator set. The site-scoped,
    global-catalog and `_kpasswd` records are in
    [Give the client the DC locator records
    (`rsat-and-kerbridge-management.md`)](../rsat-and-kerbridge-management.md#2-give-the-client-the-dc-locator-records).
    Go there if a tool continues to report that the domain is missing.
  - When you publish these records, you do not open port `389` to the LAN. See
    the firewall table below.
- **Your file server is intentionally not in that list.** The file server needs
  an A record that resolves to itself. A machine that already serves files
  almost always has this record. The file server needs **no SRV record**: the
  client builds `cifs/your-fileserver.example.site` from the name that the user
  typed. No machine must have the name `nas1`. That name is the container name
  of the included test fixture (step 5), not a name that a deployment
  publishes.

> **CAUTION:** Publish no AAAA records for any of these names. A dual-stack
> answer against Samba's IPv4-only bind makes the Windows client stall. This
> behavior was measured. The client hangs and shows no error message.

## Recipes

<details>
<summary>Route 53</summary>

```sh
aws route53 change-resource-record-sets --hosted-zone-id Z123 --change-batch '{
  "Changes": [
    {"Action":"UPSERT","ResourceRecordSet":{"Name":"kerbridge.example.site","Type":"A","TTL":300,
      "ResourceRecords":[{"Value":"192.0.2.10"}]}},
    {"Action":"UPSERT","ResourceRecordSet":{"Name":"_kerberos._udp.example.site","Type":"SRV","TTL":300,
      "ResourceRecords":[{"Value":"0 100 88 kerbridge.example.site."}]}},
    {"Action":"UPSERT","ResourceRecordSet":{"Name":"_kerberos._tcp.example.site","Type":"SRV","TTL":300,
      "ResourceRecords":[{"Value":"0 100 88 kerbridge.example.site."}]}},
    {"Action":"UPSERT","ResourceRecordSet":{"Name":"_kerbridge._tcp.example.site","Type":"SRV","TTL":300,
      "ResourceRecords":[{"Value":"0 100 443 kerbridge.example.site."}]}},
    {"Action":"UPSERT","ResourceRecordSet":{"Name":"_ldap._tcp.example.site","Type":"SRV","TTL":300,
      "ResourceRecords":[{"Value":"0 100 389 kerbridge.example.site."}]}},
    {"Action":"UPSERT","ResourceRecordSet":{"Name":"_ldap._tcp.dc._msdcs.example.site","Type":"SRV","TTL":300,
      "ResourceRecords":[{"Value":"0 100 389 kerbridge.example.site."}]}}
  ]}'
```

</details>

<details>
<summary>dnsmasq</summary>

```conf
address=/kerbridge.example.site/192.0.2.10
srv-host=_kerberos._udp.example.site,kerbridge.example.site,88,0,100
srv-host=_kerberos._tcp.example.site,kerbridge.example.site,88,0,100
srv-host=_kerbridge._tcp.example.site,kerbridge.example.site,443,0,100
srv-host=_ldap._tcp.example.site,kerbridge.example.site,389,0,100
srv-host=_ldap._tcp.dc._msdcs.example.site,kerbridge.example.site,389,0,100
```

`address=` answers both A and AAAA by default. If the host has an IPv6 address
in `/etc/hosts`, use `host-record=name,ipv4` instead. This keeps AAAA out of
the answer.

</details>

<details>
<summary>BIND zone file</summary>

```
kerbridge               IN A    192.0.2.10
_kerberos._udp          IN SRV  0 100 88  kerbridge.example.site.
_kerberos._tcp          IN SRV  0 100 88  kerbridge.example.site.
_kerbridge._tcp         IN SRV  0 100 443 kerbridge.example.site.
_ldap._tcp              IN SRV  0 100 389 kerbridge.example.site.
_ldap._tcp.dc._msdcs    IN SRV  0 100 389 kerbridge.example.site.
```

</details>

<details>
<summary>Windows DNS / any GUI provider</summary>

Create the `kerbridge` A record in the usual manner. For each SRV record, use
*Other New Records… → Service Location (SRV)*. Set Service to `_kerberos` /
`_kerbridge` / `_ldap`, Protocol to `_udp` / `_tcp`, Priority to `0`, Weight to
`100`, Port to `88` / `443` / `389`, and Host offering this service to
`kerbridge.example.site`.

Before you create `_ldap._tcp.dc._msdcs`, create the `_msdcs.example.site` and
`dc._msdcs.example.site` domains (*New Domain…*, two times). Then put the SRV
record in the inner domain.

</details>

## Giving the file server the realm zone

This section applies if the file server is not on the DC's host, and you want
the file server to resolve the realm correctly:

- Point the file server's resolver at the DC, or forward `example.site`
  conditionally to the DC. In both cases, you must first publish the DC's
  `:53`. The default configuration does not publish it: the two applicable
  lines in `deploy/compose.yaml` are commented out.
- Use **conditional forwarding, never NS delegation**. The zone is unsigned. A
  validating resolver will thus answer SERVFAIL for the zone, unless you mark
  the zone insecure (`domain-insecure` in unbound, `validate-except` in BIND).

**The `_ldap._tcp` records above do not replace this.** Those records let a
file server *find* the DC. But `net ads join` also registers the file server's
own A record into Samba's internal zone through a dynamic update. That update
needs the DC as the file server's resolver — see
[Prerequisites (`file-server.md`)](file-server.md#prerequisites).

A foreign-realm Kerberos client alone needs a smaller set of records: no
`_ldap`, no file server. That set is the client-facing subset of the record set
in [SETUP.md step 3](../../SETUP.md#3-publish-the-dns-records).

## Firewall

Open these ports inbound to the broker host, from your LAN only:

| Port | For |
|---|---|
| 88/tcp, 88/udp | Kerberos — the clients and the file server |
| 443/tcp | The broker endpoint |
| 445/tcp, 389/tcp+udp, 135/tcp, 49152–49251/tcp | Only if you manage the directory remotely, or if you run a file server on another host |
| 636/tcp | LDAPS, only if you run `kbmanage` from another host |

When you publish `_ldap._tcp`, you do not put port `389` in the first group.
The record only tells clients where the DC is. This table controls which hosts
can reach the DC. The answer stays the same: only if you run a file server on
another host, or if you manage the directory remotely.

> **CAUTION:** Do not expose port 88 to the internet. An exposed AS endpoint
> lets an attacker use the failed-password count to lock out synchronized
> accounts. This breaks issuance for those users. The broker endpoint on port
> 443 is the only endpoint that is permitted to face the internet. Expose it
> only if it is really necessary, for example when you must use ACME `HTTP-01`
> for your TLS strategy.

The other three ports each have a `*_BIND` variable in `.env`. The variable
keeps each port off the interfaces that must not serve it. `LDAPS_BIND` is
loopback-only by default. `MEMBER_BIND` and `KDC_BIND` are open, because a
member must be able to join the DC, and a client must be able to reach the KDC.
If this host also has a management interface, set `KDC_BIND` to one address.
Binding is not a replacement for the firewall above. The bind variables select
which of *this host's* addresses answer. They do not control which hosts can
reach those addresses.

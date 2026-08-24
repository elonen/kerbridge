# DNS records and firewall

This page is [step 3 (*Publish the DNS records*) in
SETUP.md](../../SETUP.md#3-publish-the-dns-records). It holds the records
themselves, recipes for four DNS servers, and the inbound firewall table.

- If your TLS strategy is `acme` or `acme-dns`, do this step **before** step 4.
  Without the records the certificate cannot be issued, and step 4 stops while
  it waits for it.
- If it is not, you can do this step at the same time as step 4. But you must
  complete it before a client can work.

## The records

Publish these records in the zone that your **LAN clients** use. Do not publish
them in Samba's internal DNS. The DC operates its own DNS server for its own
use, and the records there can contain addresses to which your clients have no
route. This split is intentional.

```
kerbridge.example.site            A     <broker host LAN IP>

_kerbridge._tcp.example.site      SRV   0 100 443 kerbridge.example.site.

_kerberos._udp.example.site       SRV   0 100 88  kerbridge.example.site.
_kerberos._tcp.example.site       SRV   0 100 88  kerbridge.example.site.

_ldap._tcp.example.site           SRV   0 100 389 kerbridge.example.site.
_ldap._tcp.dc._msdcs.example.site SRV   0 100 389 kerbridge.example.site.
```

- **`_kerbridge._tcp`** is KerBridge's own record. A client with no
  configuration finds the broker through it. The user types no URL, and you
  push no registry value.
- **`_kerberos._udp`** is the record that Windows queries. Publish
  `_kerberos._tcp` also. It has no cost, and other clients use it.
- **The two `_ldap._tcp` records** are the DC-locator pair. The workstation of
  step 7 is a foreign-realm Kerberos client, and it never queries them. Each
  tool that must find the DC *as a DC* needs them: RSAT and ADUC on an unjoined
  machine, and a domain member that resolves the realm through this zone.
- **Your file server is not in this list, and this is intentional.** It needs
  an A record that resolves to itself, and a machine that already serves files
  almost always has one. It needs no SRV record: the client builds
  `cifs/your-fileserver.example.site` from the name that the user typed.

> **CAUTION: Publish no AAAA record for any of these names.** Samba binds to
> IPv4 only. A dual-stack answer makes the Windows client stop and wait. This
> behavior was measured. The client hangs, and it shows no error message.

<details>
<summary>One <code>_kerbridge._tcp</code> record covers every subdomain</summary>

A client with the DNS suffix `usr.example.site` queries that zone first, and
then queries the parent zone `example.site`. So it finds the record without a
copy in each subdomain. The client would in fact *refuse* a copy in a
subdomain, because the target `kerbridge.example.site` is outside the subdomain
that answered. Publish the record one time, in the zone that contains the
broker. The upward search stops at two labels, so it never reaches a bare TLD.

If a client does not find the address, read `%APPDATA%\KerBridge\kerbridge.log`.
The log shows the names that the client tried, and the reason that it refused
an answer.

</details>

<details>
<summary>The full DC-locator set, if a tool still cannot find the domain</summary>

The two `_ldap._tcp` records above are not the full locator set. The
site-scoped, global-catalog and `_kpasswd` records are in
[Give the client the DC locator records
(`rsat-and-kerbridge-management.md`)](../rsat-and-kerbridge-management.md#2-give-the-client-the-dc-locator-records).

To publish `_ldap._tcp` does not open port `389` to the LAN. The record tells a
client where the DC is. The firewall table below controls which hosts can reach
it.

</details>

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

`address=` answers both A and AAAA. If the host has an IPv6 address in
`/etc/hosts`, use `host-record=name,ipv4` instead. This keeps AAAA out of the
answer.

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
<summary>Windows DNS, or any GUI provider</summary>

Create the `kerbridge` A record in the usual manner. For each SRV record, use
*Other New Records… → Service Location (SRV)*. Set Service to `_kerberos`,
`_kerbridge` or `_ldap`, Protocol to `_udp` or `_tcp`, Priority to `0`, Weight
to `100`, Port to `88`, `443` or `389`, and *Host offering this service* to
`kerbridge.example.site`.

Before you create `_ldap._tcp.dc._msdcs`, create the `_msdcs.example.site` and
`dc._msdcs.example.site` domains with *New Domain…*, two times. Then put the
SRV record in the inner domain.

</details>

## Give the file server the realm zone

Do this if the file server is not on the DC's host. The file server must
resolve the AD zone from the DC:

- Point the file server's resolver at the DC, or forward `example.site`
  conditionally to the DC. For both, publish the DC's port `:53` first. The
  default configuration does not publish it: the two lines in
  `deploy/compose.yaml` are commented out.
- Use **conditional forwarding, never NS delegation.** The zone is unsigned, so
  a validating resolver answers SERVFAIL for it. To keep DNSSEC validation for
  your other zones, mark this one insecure: `domain-insecure` in unbound, or
  `validate-except` in BIND.

The `_ldap._tcp` records above do not replace this. Those records let a file
server *find* the DC. But `net ads join` also registers the file server's own A
record in Samba's internal zone through a dynamic update, and that update needs
the DC as the file server's resolver —
[Prerequisites (`file-server.md`)](file-server.md#prerequisites).

## Firewall

Open these ports inbound to the broker host, from your LAN only:

| Port | For |
|---|---|
| 88/tcp, 88/udp | Kerberos — the clients and the file server |
| 443/tcp | The broker endpoint |
| 445/tcp, 389/tcp+udp, 135/tcp, 49152–49251/tcp | Only if you manage the directory remotely, or if your file server is on another host |
| 636/tcp | LDAPS, only if you run `kbmanage` from another host |

> **CAUTION: Do not expose port 88 to the internet.** An exposed AS endpoint
> lets an attacker use the failed-password count to lock out the synchronized
> accounts. This stops issuance for those users. Port 443 is the only port that
> may face the internet, and expose it only if you must, for example when your
> TLS strategy is ACME `HTTP-01`.

<details>
<summary>The <code>*_BIND</code> variables, and why they are not a firewall</summary>

Each of the other ports has a `*_BIND` variable in `.env`, which keeps the port
off the interfaces that must not serve it. `LDAPS_BIND` is loopback-only by
default. `MEMBER_BIND` and `KDC_BIND` are open, because a member must be able
to join the DC and a client must be able to reach the KDC. If this host also
has a management interface, set `KDC_BIND` to one address.

The bind variables select which of *this host's* addresses answer. They do not
control which hosts can reach those addresses. The firewall does that.

A package-installed Samba ignores all of this: `bind interfaces only` is
per-interface, not per-port, so a Debian deployment serves every Samba service
on every interface. See
[`debian-deployment.md`](debian-deployment.md#provision-the-realm).

</details>

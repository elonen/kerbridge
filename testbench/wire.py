#!/usr/bin/env python3
"""Session-A wire reader for the Entra-joined spike.

Reads the rotating tcpdump captures in evidence/ and prints a decoded,
UTC-stamped ladder for a time window.  Built because there is no tshark on the
VM and rows 5/7 are entirely about KRB error codes and TGS-REP packet sizes.

  wire.py <cap> <fromUTC> <toUTC>        cap: frag88 | ws | member | dc

Decodes:
  port 88   Kerberos: msg-type (AS/TGS REQ/REP, KRB-ERROR), error-code, sname,
            transport (UDP / TCP), IP fragmentation, TCP SYN/RST/FIN
  port 445  SMB2: command + NTStatus, and an NTLMSSP flag on the payload
Times are UTC.  Accepts 'HH:MM:SS' or 'HH:MM:SS.mmm' (today) or full ISO.
"""
import sys, glob, struct, datetime, os

# Directory holding the rotating tcpdump captures. Override with WIRE_EVIDENCE_DIR.
EV = os.environ.get("WIRE_EVIDENCE_DIR", "evidence")

KRB_MSG = {10: "AS-REQ", 11: "AS-REP", 12: "TGS-REQ", 13: "TGS-REP",
           14: "AP-REQ", 15: "AP-REP", 30: "KRB-ERROR"}
KRB_ERR = {6: "C_PRINCIPAL_UNKNOWN", 7: "S_PRINCIPAL_UNKNOWN",
           12: "POLICY", 13: "BADOPTION", 18: "CLIENT_REVOKED",
           23: "KEY_EXPIRED", 24: "PREAUTH_FAILED", 25: "PREAUTH_REQUIRED",
           31: "BAD_INTEGRITY", 32: "TKT_EXPIRED", 37: "SKEW",
           52: "RESPONSE_TOO_BIG"}
SMB2_CMD = {0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT",
            4: "TREE_DISCONNECT", 5: "CREATE", 6: "CLOSE", 8: "READ", 9: "WRITE",
            14: "QUERY_DIRECTORY", 16: "QUERY_INFO"}
SMB_STATUS = {0x00000000: "SUCCESS", 0xC000006D: "LOGON_FAILURE",
              0xC0000022: "ACCESS_DENIED", 0xC0000016: "MORE_PROCESSING_REQUIRED",
              0xC000000D: "INVALID_PARAMETER", 0xC0000203: "USER_SESSION_DELETED",
              0xC00000BB: "NOT_SUPPORTED", 0xC0000034: "OBJECT_NAME_NOT_FOUND",
              0x80000006: "NO_MORE_FILES", 0xC0000225: "NOT_FOUND",
              0xC000015B: "LOGON_TYPE_NOT_GRANTED", 0xC0000064: "NO_SUCH_USER",
              0xC000018B: "NO_TRUST_SAM_ACCOUNT", 0xC0000234: "ACCOUNT_LOCKED_OUT",
              0xC0000072: "ACCOUNT_DISABLED", 0xC0000193: "ACCOUNT_EXPIRED"}


# ---------- minimal DER ----------
def der_len(b, i):
    n = b[i]; i += 1
    if n < 0x80:
        return n, i
    k = n & 0x7F
    return int.from_bytes(b[i:i + k], "big"), i + k


def der_iter(b, i, end):
    """Yield (tag, content_start, content_end) for each TLV in [i,end)."""
    while i < end:
        t = b[i]; i += 1
        if t & 0x1F == 0x1F:                      # multi-byte tag, not needed here
            while b[i] & 0x80:
                i += 1
            i += 1
        ln, i = der_len(b, i)
        if ln < 0 or i + ln > end:
            return
        yield t, i, i + ln
        i += ln


def der_int(b, i, end):
    return int.from_bytes(b[i:end], "big")


def der_str(b, i, end):
    return b[i:end].decode("ascii", "replace")


def krb_decode(p):
    """p = raw Kerberos message. -> dict(msg, err, errname, sname, cname)."""
    out = {}
    if len(p) < 2 or (p[0] & 0xC0) != 0x40:       # APPLICATION class, constructed
        return out
    app = p[0] & 0x1F
    out["msg"] = KRB_MSG.get(app, f"app{app}")
    ln, i = der_len(p, 1)
    end = min(i + ln, len(p))
    # inside: SEQUENCE
    for t, s, e in der_iter(p, i, end):
        if t != 0x30:
            continue
        for ft, fs, fe in der_iter(p, s, e):      # [n] context fields
            n = ft & 0x1F
            for it, iss, ie in der_iter(p, fs, fe):
                if app == 30 and n == 6 and it == 0x02:
                    out["err"] = der_int(p, iss, ie)
                    out["errname"] = KRB_ERR.get(out["err"], "?")
                if it == 0x30 or it == 0x02 or it == 0x1B:
                    pass
            # principal names: PrincipalName ::= SEQ { [0] type, [1] SEQ OF GeneralString }
            if ft in (0xA1, 0xA2, 0xA3, 0xA4, 0xA5):
                parts = _princ(p, fs, fe)
                if parts:
                    key = "cname" if ft in (0xA1,) and app in (12, 10) else None
                    out.setdefault("names", []).append("/".join(parts))
                    _ = key
            if ft == 0xA2 and app == 30:          # KRB-ERROR realm is [9]; keep simple
                pass
        break
    return out


def _princ(b, i, end):
    parts = []
    for t, s, e in der_iter(b, i, end):
        if t == 0x30:
            for ft, fs, fe in der_iter(b, s, e):
                if ft == 0xA1:
                    for it, iss, ie in der_iter(b, fs, fe):
                        if it == 0x30:
                            for gt, gs, ge in der_iter(b, iss, ie):
                                if gt == 0x1B:
                                    parts.append(der_str(b, gs, ge))
    return parts


def krb_names(p):
    """Grep GeneralStrings out of a Kerberos message (cheap, order-preserving)."""
    names, i = [], 0
    while i < len(p) - 2:
        if p[i] == 0x1B:
            ln, j = der_len(p, i + 1)
            if 0 < ln < 64 and j + ln <= len(p):
                s = p[j:j + ln]
                if all(32 <= c < 127 for c in s):
                    names.append(s.decode())
                    i = j + ln
                    continue
        i += 1
    return names


# ---------- pcap ----------
def frames(paths):
    for path in paths:
        with open(path, "rb") as f:
            gh = f.read(24)
            if len(gh) < 24:
                continue
            magic = gh[:4]
            if magic == b"\xd4\xc3\xb2\xa1":
                end, nano = "<", False
            elif magic == b"\xa1\xb2\xc3\xd4":
                end, nano = ">", False
            elif magic == b"\x4d\x3c\xb2\xa1":
                end, nano = "<", True
            elif magic == b"\xa1\xb2\x3c\x4d":
                end, nano = ">", True
            else:
                continue
            while True:
                ph = f.read(16)
                if len(ph) < 16:
                    break
                ts, tu, cap, orig = struct.unpack(end + "IIII", ph)
                data = f.read(cap)
                if len(data) < cap:
                    break
                t = ts + (tu / 1e9 if nano else tu / 1e6)
                yield t, data, orig


def parse(data):
    """Ethernet -> IP -> proto. Returns dict or None."""
    if len(data) < 34:
        return None
    et = struct.unpack("!H", data[12:14])[0]
    off = 14
    if et == 0x8100:
        et = struct.unpack("!H", data[16:18])[0]
        off = 18
    if et != 0x0800:
        return None
    ip = data[off:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    tot = struct.unpack("!H", ip[2:4])[0]
    ipid = struct.unpack("!H", ip[4:6])[0]
    flfr = struct.unpack("!H", ip[6:8])[0]
    mf = bool(flfr & 0x2000)
    fo = (flfr & 0x1FFF) * 8
    proto = ip[9]
    src = ".".join(str(x) for x in ip[12:16])
    dst = ".".join(str(x) for x in ip[16:20])
    r = dict(src=src, dst=dst, proto=proto, ipid=ipid, mf=mf, fo=fo,
             iplen=tot, wire=len(data))
    pay = ip[ihl:tot] if tot else ip[ihl:]
    if fo:                                        # non-first fragment: no L4 header
        r.update(sport=None, dport=None, payload=b"", frag=True)
        return r
    r["frag"] = mf
    if proto == 17 and len(pay) >= 8:
        r["sport"], r["dport"] = struct.unpack("!HH", pay[:4])
        r["payload"] = pay[8:]
    elif proto == 6 and len(pay) >= 20:
        r["sport"], r["dport"] = struct.unpack("!HH", pay[:4])
        doff = (pay[12] >> 4) * 4
        r["flags"] = pay[13]
        r["payload"] = pay[doff:]
    else:
        return None
    return r


def tcpflags(f):
    s = ""
    for bit, ch in ((0x02, "S"), (0x10, "A"), (0x01, "F"), (0x04, "R"), (0x08, "P")):
        if f & bit:
            s += ch
    return s or "-"


def smb2(pay):
    """Yield (cmd, status, is_resp) for each SMB2 PDU in a NBSS stream chunk."""
    i = 0
    while i + 4 <= len(pay):
        ln = struct.unpack("!I", pay[i:i + 4])[0] & 0xFFFFFF
        body = pay[i + 4:i + 4 + ln]
        i += 4 + ln
        if len(body) < 64 or body[:4] not in (b"\xfeSMB", b"\xfdSMB"):
            continue
        cmd = struct.unpack("<H", body[12:14])[0]
        status = struct.unpack("<I", body[8:12])[0]
        flags = struct.unpack("<I", body[16:20])[0]
        tid = struct.unpack("<I", body[36:40])[0]
        sid = struct.unpack("<Q", body[40:48])[0]
        yield cmd, status, bool(flags & 1), tid, sid


def tparse(s):
    s = s.strip()
    if "T" in s:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    return datetime.datetime.fromisoformat(f"{today}T{s}+00:00").timestamp()


def main():
    cap, t0, t1 = sys.argv[1], tparse(sys.argv[2]), tparse(sys.argv[3])
    paths = sorted(glob.glob(f"{EV}/{cap}.pcap*"))
    paths = [p for p in paths if not p.endswith(".log")]
    if not paths:
        print(f"no captures matching {cap}", file=sys.stderr)
        sys.exit(1)
    print(f"# {cap}: {os.path.basename(paths[0])}..{os.path.basename(paths[-1])}  "
          f"window {sys.argv[2]}..{sys.argv[3]} UTC")
    n88 = n445 = 0
    for t, data, orig in frames(paths):
        if not (t0 <= t <= t1):
            continue
        r = parse(data)
        if not r:
            continue
        ts = datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        sp, dp = r.get("sport"), r.get("dport")
        arrow = f"{r['src']}->{r['dst']}"
        # ---- port 88 ----
        if 88 in (sp, dp) or (r["fo"] and r["proto"] == 17):
            n88 += 1
            proto = "UDP" if r["proto"] == 17 else "TCP"
            frag = ""
            if r["fo"] or r["mf"]:
                frag = f" FRAG id={r['ipid']} off={r['fo']}{'+MF' if r['mf'] else ''}"
            extra = ""
            if r["proto"] == 6:
                extra = f" [{tcpflags(r['flags'])}]"
            pay = r["payload"]
            l4 = len(pay)                         # TCP/UDP payload == phase-5's ladder measure
            if r["proto"] == 6 and len(pay) >= 4:
                pay = pay[4:]                     # strip TCP length prefix
            k = krb_decode(pay) if pay else {}
            desc = ""
            if k.get("msg"):
                desc = f" {k['msg']} L4={l4}"
                if "err" in k:
                    desc += f" err={k['err']} {k.get('errname','?')}"
                nm = krb_names(pay)
                if nm:
                    desc += "  names=" + ",".join(nm[:10])
            print(f"{ts} 88  {proto}{extra} {arrow} iplen={r['iplen']} wire={orig}{frag}{desc}")
        # ---- port 445 ----
        elif 445 in (sp, dp):
            pay = r["payload"]
            if not pay:
                if r["proto"] == 6 and r["flags"] & 0x07:   # SYN/FIN/RST only
                    print(f"{ts} 445 TCP [{tcpflags(r['flags'])}] {arrow}")
                continue
            n445 += 1
            ntlm = " NTLMSSP" if b"NTLMSSP\x00" in pay else ""
            spnego = " SPNEGO" if b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02" in pay else ""
            got = False
            for cmd, status, is_resp, tid, sid in smb2(pay):
                got = True
                # Status is only meaningful in a RESPONSE; in a request those 4 bytes
                # are ChannelSequence+Reserved and printing them reads as a bogus code.
                st = (f"0x{status:08x} {SMB_STATUS.get(status, '?'):<25}"
                      if is_resp else " " * 36)
                print(f"{ts} 445 {arrow} {'RESP' if is_resp else 'REQ '} "
                      f"{SMB2_CMD.get(cmd, cmd):<15} {st} "
                      f"sid={sid & 0xffffffff:08x} tid={tid:08x} "
                      f"len={len(pay)}{ntlm}{spnego}")
            if not got:
                print(f"{ts} 445 {arrow} (cont) len={len(pay)}{ntlm}{spnego}")
    print(f"# totals: port88 frames={n88}  port445 pdus={n445}")


if __name__ == "__main__":
    main()

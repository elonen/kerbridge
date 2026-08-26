//! The Linux arm of [`super`]: the resolver's configuration, read directly, and
//! one UDP query. Part of the CI-only Linux arm -- see [`crate::os`] for what
//! that is and is not.
//!
//! **Why not `res_query`, which is what the macOS arm calls.** `libresolv` is a
//! glibc-ism here: musl ships an empty `libresolv.a` for link compatibility and
//! puts a much reduced resolver in `libc` itself, and the CI images this arm is
//! built for are not all glibc. Linking a symbol that resolves on the developer's
//! machine and not in the container is the failure this avoids -- and doing it in
//! `std` costs no `unsafe`, no C string round-trip and no second guess about
//! `struct __res_state`. What it gives up is `nsswitch.conf`: this asks the
//! nameservers in `/etc/resolv.conf` and nothing else, so a host resolved by
//! `mdns` or `myhostname` is invisible to it. Neither can hold an SRV record, so
//! nothing is lost that this lookup could have used.
//!
//! **The answer is parsed here**, the same as on macOS and for the same reason:
//! there is no library call that hands back a parsed SRV. That parser is
//! therefore the second copy of a DNS message walk in this tree, kept separate
//! because consolidating it means editing the macOS arm, which nothing on Linux
//! can build or test. A third arm needing one is the moment to lift a shared
//! reader out of both.
//!
//! Everything the *policy* depends on -- which zones to ask, and that a target
//! must live inside the zone that answered -- is in [`super`], once, with its own
//! tests. This file is transport.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use super::Srv;

/// Where the resolver's configuration lives. Written by the DHCP client, by
/// `systemd-resolved`, or by Docker for a container; every one of them puts the
/// nameservers and the search list in this file in this format.
const RESOLV_CONF: &str = "/etc/resolv.conf";

const CLASS_IN: u16 = 1;
const TYPE_SRV: u16 = 33;

/// Long enough for any answer that fits a datagram, and the ceiling the protocol
/// puts on one without EDNS0. A longer answer arrives truncated, which this
/// treats as no answer -- see [`lookup_srv`].
const ANSWER_MAX: usize = 512;

/// Per nameserver, and the resolver's own default. A machine whose first
/// nameserver is unreachable therefore costs this many seconds before the second
/// is tried, which is the same bargain `resolv.conf` makes.
const TIMEOUT: Duration = Duration::from_secs(5);

/// The DNS domains this machine is in, from the resolver's search list.
///
/// `domain` names one and `search` names several; a later directive replaces an
/// earlier one for the resolver, but both are kept here for the reason the macOS
/// arm gives -- an extra zone to ask costs one NXDOMAIN, and a zone missed costs
/// the whole discovery.
pub fn own_domains() -> Vec<String> {
    let text = std::fs::read_to_string(RESOLV_CONF).unwrap_or_default();
    let mut out = words(&text, "search");
    out.extend(words(&text, "domain"));
    out
}

/// Every whitespace-separated word of every `keyword` line in a `resolv.conf`.
///
/// Takes the text rather than reading the file, so the parsing is testable
/// without one -- what the real file contains is the machine's business and not
/// something a test may assert.
fn words(text: &str, keyword: &str) -> Vec<String> {
    let prefix = format!("{keyword} ");
    text.lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix(&prefix))
        .flat_map(str::split_whitespace)
        .map(str::to_owned)
        .collect()
}

/// One SRV query, to each configured nameserver until one answers.
///
/// Anything other than a successful answer -- NXDOMAIN, no resolver, a timeout,
/// a truncated response, a malformed one -- is an empty result: this is a lookup
/// *expected* to find nothing on most networks, and [`super::discover_broker`]
/// treats a silent `None` as the ordinary case rather than an error worth
/// showing.
pub fn lookup_srv(name: &str) -> Vec<Srv> {
    let Some(question) = encode_name(name) else {
        return Vec::new();
    };
    for server in nameservers() {
        let id = query_id();
        let mut query = Vec::with_capacity(question.len() + 16);
        query.extend(id.to_be_bytes());
        // Recursion desired, and nothing else: no truncation, no authority.
        query.extend([0x01, 0x00]);
        query.extend([0x00, 0x01]); // qdcount
        query.extend([0x00; 6]); // ancount, nscount, arcount
        query.extend(&question);
        query.extend(TYPE_SRV.to_be_bytes());
        query.extend(CLASS_IN.to_be_bytes());

        let Some(answer) = exchange(server, &query) else {
            continue;
        };
        // The id and the echoed question are what tie this datagram to the
        // question asked. Without both checks a stray or forged packet on the
        // ephemeral port is read as the answer.
        if answer.len() < 12 || answer[..2] != id.to_be_bytes() || !echoes(&answer, &question) {
            continue;
        }
        // Truncated: the real answer is longer than a datagram. Retrying over TCP
        // is what a full resolver does; a `_kerbridge._tcp` RRset that does not
        // fit in 512 bytes is a deployment this client cannot serve anyway, so
        // this reports no answer rather than growing a second transport.
        if answer[2] & 0x02 != 0 {
            crate::log::warn(&format!("{name}: the SRV answer was truncated; ignoring it"));
            continue;
        }
        return parse(&answer);
    }
    Vec::new()
}

/// The `nameserver` lines, in file order. A resolver reads at most three; this
/// reads them all, because the cost of a fourth is one timeout on a machine that
/// is already misconfigured.
fn nameservers() -> Vec<SocketAddr> {
    let text = std::fs::read_to_string(RESOLV_CONF).unwrap_or_default();
    words(&text, "nameserver")
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
}

/// A fresh query id. Not security in itself -- an answer here can only name a
/// host inside the zone that answered, and the URL is still validated against
/// the trust store -- but a predictable id makes an off-path answer free, and
/// this client already carries a CSPRNG for PKCE.
fn query_id() -> u16 {
    let mut b = [0u8; 2];
    // A failure here is an OS with no entropy source, which is not a state this
    // process survives elsewhere either; fall back rather than fail the lookup.
    if getrandom::fill(&mut b).is_err() {
        return 0x4b42;
    }
    u16::from_be_bytes(b)
}

/// Send and receive one datagram. `None` for any failure, including the timeout.
fn exchange(server: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
    // Bound to the server's own family: a v4 socket cannot reach a v6 nameserver
    // and the connect would simply fail.
    let bind = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.set_read_timeout(Some(TIMEOUT)).ok()?;
    // Connected, so the kernel drops datagrams from anywhere else before this
    // code has to think about them.
    socket.connect(server).ok()?;
    socket.send(query).ok()?;
    let mut buf = vec![0u8; ANSWER_MAX];
    let n = socket.recv(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

/// True when the response repeats the question that was asked, which is the
/// second half of matching an answer to its query.
fn echoes(answer: &[u8], question: &[u8]) -> bool {
    let end = 12 + question.len() + 4;
    answer.len() >= end
        && answer[12..12 + question.len()].eq_ignore_ascii_case(question)
        && answer[12 + question.len()..end] == [0, TYPE_SRV as u8, 0, CLASS_IN as u8]
}

/// A domain name in wire format: each label length-prefixed, terminated by a
/// zero-length root label. `None` for a name no query could carry -- an empty or
/// over-long label, or a name past the 255-byte ceiling.
fn encode_name(name: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend(label.as_bytes());
    }
    out.push(0);
    (out.len() <= 255).then_some(out)
}

/// Walk a DNS response, keeping the SRV records in the answer section.
///
/// Every step is bounds-checked against the message that arrived, and a
/// malformed one stops the walk rather than being reported: a broken answer and
/// no answer lead to the same place, which is the next domain to try.
fn parse(msg: &[u8]) -> Vec<Srv> {
    let mut out = Vec::new();
    if msg.len() < 12 {
        return out;
    }
    // RCODE: anything but NOERROR (0) has no answer section worth walking.
    if msg[3] & 0x0f != 0 {
        return out;
    }
    let questions = be16(msg, 4);
    let answers = be16(msg, 6);

    let mut at = 12usize;
    for _ in 0..questions {
        let Some(next) = skip_name(msg, at) else {
            return out;
        };
        // QTYPE and QCLASS.
        at = next + 4;
    }
    for _ in 0..answers {
        let Some(next) = skip_name(msg, at) else {
            return out;
        };
        at = next;
        // TYPE, CLASS, TTL, RDLENGTH.
        if at + 10 > msg.len() {
            return out;
        }
        let rtype = be16(msg, at);
        let rdlen = be16(msg, at + 8) as usize;
        at += 10;
        if at + rdlen > msg.len() {
            return out;
        }
        // priority, weight, port, then the target name.
        if rtype == TYPE_SRV
            && rdlen >= 7
            && let Some(target) = expand(msg, at + 6)
        {
            out.push(Srv {
                target,
                priority: be16(msg, at),
                weight: be16(msg, at + 2),
                port: be16(msg, at + 4),
            });
        }
        at += rdlen;
    }
    out
}

fn be16(msg: &[u8], at: usize) -> u16 {
    match (msg.get(at), msg.get(at + 1)) {
        (Some(&hi), Some(&lo)) => u16::from_be_bytes([hi, lo]),
        _ => 0,
    }
}

/// The offset just past the name starting at `at`, following a compression
/// pointer to measure the name but not to read it.
fn skip_name(msg: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *msg.get(at)? as usize;
        match len {
            // Root label: the name ends here.
            0 => return Some(at + 1),
            // A pointer is two bytes and always terminal.
            _ if len & 0xc0 == 0xc0 => return (at + 1 < msg.len()).then_some(at + 2),
            // Any other high bits are a label type this protocol no longer has.
            _ if len & 0xc0 != 0 => return None,
            _ => at += len + 1,
        }
    }
}

/// The name at `at`, with compression pointers followed.
///
/// A pointer may only point *backwards*, which is what RFC 1035 requires and
/// what makes the walk terminate: a message crafted to point forwards or at
/// itself would otherwise loop here forever. That single rule is the whole
/// termination argument, so it is enforced rather than assumed.
fn expand(msg: &[u8], mut at: usize) -> Option<String> {
    let mut labels: Vec<&str> = Vec::new();
    let mut furthest = at;
    loop {
        let len = *msg.get(at)? as usize;
        match len {
            0 => return Some(labels.join(".")),
            _ if len & 0xc0 == 0xc0 => {
                let target = ((len & 0x3f) << 8) | *msg.get(at + 1)? as usize;
                if target >= furthest {
                    return None;
                }
                furthest = target;
                at = target;
            }
            _ if len & 0xc0 != 0 => return None,
            _ => {
                let (from, to) = (at + 1, at + 1 + len);
                labels.push(std::str::from_utf8(msg.get(from..to)?).ok()?);
                at = to;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `_kerbridge._tcp` answer, byte for byte, with the target reached
    /// through a compression pointer back into the question -- which is how every
    /// resolver actually encodes it, and the reason [`expand`] exists at all.
    fn answer() -> Vec<u8> {
        let mut m = Vec::new();
        m.extend([0x12, 0x34]); // id
        m.extend([0x81, 0x80]); // response, recursion available, rcode 0
        m.extend([0x00, 0x01]); // qdcount
        m.extend([0x00, 0x01]); // ancount
        m.extend([0x00, 0x00, 0x00, 0x00]); // nscount, arcount
        m.extend(b"\x0a_kerbridge\x04_tcp\x07example\x04site\x00");
        m.extend([0x00, 0x21, 0x00, 0x01]); // SRV, IN
        m.extend([0xc0, 0x0c]); // name: pointer to offset 12
        m.extend([0x00, 0x21, 0x00, 0x01]); // SRV, IN
        m.extend([0x00, 0x00, 0x01, 0x2c]); // ttl
        let rdata_at = m.len();
        m.extend([0x00, 0x00]); // rdlength, filled in below
        m.extend([0x00, 0x00]); // priority 0
        m.extend([0x00, 0x64]); // weight 100
        m.extend([0x01, 0xbb]); // port 443
        // "kerbridge", then a pointer to "example.site" inside the question.
        m.extend(b"\x09kerbridge");
        m.extend([0xc0, (12 + 16) as u8]);
        let rdlen = (m.len() - rdata_at - 2) as u16;
        m[rdata_at..rdata_at + 2].copy_from_slice(&rdlen.to_be_bytes());
        m
    }

    #[test]
    fn reads_a_compressed_srv_answer() {
        let records = parse(&answer());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].target, "kerbridge.example.site");
        assert_eq!(records[0].port, 443);
        assert_eq!(records[0].priority, 0);
        assert_eq!(records[0].weight, 100);
    }

    /// A response cut off mid-record must yield nothing rather than read past it,
    /// and must not panic at any length.
    #[test]
    fn a_truncated_answer_is_no_answer() {
        let full = answer();
        for cut in 0..full.len() {
            let _ = parse(&full[..cut]);
        }
        assert!(parse(&full[..full.len() - 4]).is_empty());
        assert!(parse(&[]).is_empty());
    }

    /// NXDOMAIN carries a question and no answers, and is the ordinary reply on
    /// a network that publishes no such record.
    #[test]
    fn an_error_rcode_has_no_records() {
        let mut m = answer();
        m[3] |= 0x03; // NXDOMAIN
        assert!(parse(&m).is_empty());
    }

    /// A compression pointer that points forwards, or at itself, is the shape
    /// that turns a parser into an infinite loop. It has to terminate.
    #[test]
    fn a_forward_pointer_does_not_loop() {
        let mut m = answer();
        // Aim the target name's pointer at itself instead of back at the
        // question. Its two bytes are the last of the message.
        let end = m.len();
        let self_at = end - 2;
        m[self_at] = 0xc0 | (self_at >> 8) as u8;
        m[self_at + 1] = self_at as u8;
        assert!(parse(&m).is_empty());
    }

    /// The question a query carries, and the check that an answer echoes it.
    #[test]
    fn a_name_round_trips_through_the_wire_format() {
        let q = encode_name("_kerbridge._tcp.example.site").expect("a valid name");
        assert_eq!(q, b"\x0a_kerbridge\x04_tcp\x07example\x04site\x00");
        // A trailing dot is the same name.
        assert_eq!(encode_name("example.site.").unwrap(), b"\x07example\x04site\x00");
        // Neither of these can go on the wire.
        assert!(encode_name("a..b").is_none());
        assert!(encode_name(&format!("{}.site", "x".repeat(64))).is_none());
        assert!(encode_name(&"label.".repeat(50)).is_none());

        let m = answer();
        assert!(echoes(&m, &q));
        // The same query against a different name is not this answer.
        assert!(!echoes(&m, &encode_name("_kerbridge._tcp.other.site").unwrap()));
    }

    /// `search` and `domain` both feed the zone list, and a comment or an
    /// unrelated directive must not.
    #[test]
    fn the_search_list_is_read_a_word_at_a_time() {
        // Docker's own generated file, near enough: a comment, a container
        // resolver, both directives that name a zone, and one that names none.
        let text = "# Generated by Docker\nnameserver 127.0.0.11\nnameserver fd00::1\n\
                    search usr.example.site example.site\noptions ndots:0\n\
                    domain example.site\n";
        assert_eq!(words(text, "search"), ["usr.example.site", "example.site"]);
        assert_eq!(words(text, "domain"), ["example.site"]);
        assert_eq!(words(text, "nameserver"), ["127.0.0.11", "fd00::1"]);
        // `searchdomain` is not `search`, and a bare keyword names nothing.
        assert!(words("searchdomain example.site\nsearch\n", "search").is_empty());
        assert!(words("", "search").is_empty());
    }
}

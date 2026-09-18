//! Pure connection-surface logic: state classification, grouping identity, and
//! endpoint rendering.
//!
//! Deliberately free of `windows` bindings and of `crate::` imports so the rules
//! can be exercised without Windows FFI, and so a bug here cannot hide behind a
//! failing API call. `self_checks()` runs the assertions for real, from the
//! shipped binary: `amon --selftest`.

use std::net::{Ipv4Addr, Ipv6Addr};

/// States that mean "a socket exists right now".
///
/// LISTEN belongs to the listener surface; CLOSED / TIME_WAIT / DELETE_TCB rows
/// linger after the socket is gone, and counting them would invent conversations
/// nobody is having. FIN_WAIT1/2 and CLOSE_WAIT **are** live: a half-closed socket
/// can still be sending.
pub fn is_live_tcp_state(state: u32) -> bool {
    !matches!(state, 1 | 2 | 11 | 12)
}

pub fn tcp_state_name(state: u32) -> &'static str {
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        100 => "RESERVED",
        _ => "UNKNOWN",
    }
}

/// Group identity: **(owner pid, peer)** — deliberately *not* the process name.
///
/// Name resolution needs an `OpenProcess` handle and can flap between a real name
/// and `?` for the same socket; embedding the name would turn that into a
/// fabricated close+open pair for a conversation that never changed.
pub fn group_key(pid: u32, remote: &str) -> String {
    format!("{pid}|{remote}")
}

/// `[addr%scope]:port` — the scope id is what makes a link-local peer unambiguous.
///
/// `port_net_order` is the **raw value from the MIB row**, which Windows reports in
/// network byte order in the low 16 bits — exactly like `MIB_TCPROW`. Callers must
/// pass it through unchanged; the byte swap happens here and only here.
pub fn v6_endpoint(addr: Ipv6Addr, scope: u32, port_net_order: u32) -> String {
    let port = u16::from_be(port_net_order as u16);
    if scope != 0 {
        format!("[{addr}%{scope}]:{port}")
    } else {
        format!("[{addr}]:{port}")
    }
}

/// Is this peer a loopback peer?
///
/// `Ipv6Addr::is_loopback()` only recognises `::1`, so a dual-stack socket whose
/// peer is expressed as `::ffff:127.0.0.1` would otherwise leak through the
/// default "hide loopback" filter.
pub fn is_loopback_peer_v6(addr: Ipv6Addr) -> bool {
    addr.is_loopback()
        || addr
            .to_ipv4_mapped()
            .map(|v4: Ipv4Addr| v4.is_loopback())
            .unwrap_or(false)
}

/// Rules that can be checked without a network. Returns (name, ok, detail).
pub fn self_checks() -> Vec<(&'static str, bool, String)> {
    let mut out: Vec<(&'static str, bool, String)> = Vec::new();
    let mut check = |name: &'static str, ok: bool, detail: String| out.push((name, ok, detail));

    // 1. state classification
    let dead = [1u32, 2, 11, 12];
    let live = [3u32, 4, 5, 6, 7, 8, 9, 10, 42];
    check(
        "state: LISTEN/CLOSED/TIME_WAIT/DELETE_TCB are not conversations",
        dead.iter().all(|&s| !is_live_tcp_state(s)),
        format!("{:?}", dead.map(is_live_tcp_state)),
    );
    check(
        "state: SYN_SENT/ESTABLISHED/FIN_WAIT*/CLOSE_WAIT/unknown are live",
        live.iter().all(|&s| is_live_tcp_state(s)),
        format!("{:?}", live.map(is_live_tcp_state)),
    );
    check(
        "state: names round-trip",
        tcp_state_name(5) == "ESTABLISHED"
            && tcp_state_name(2) == "LISTEN"
            && tcp_state_name(11) == "TIME_WAIT"
            && tcp_state_name(4242) == "UNKNOWN",
        format!(
            "{}/{}/{}/{}",
            tcp_state_name(5),
            tcp_state_name(2),
            tcp_state_name(11),
            tcp_state_name(4242)
        ),
    );

    // 2. grouping identity ignores the process name
    let a = group_key(23088, "154.82.20.63:443");
    let b = group_key(23088, "154.82.20.63:443");
    check(
        "group key: stable for same pid+peer",
        a == b && a == "23088|154.82.20.63:443",
        a.clone(),
    );
    check(
        "group key: differs across pid or peer",
        group_key(1, "1.1.1.1:443") != group_key(2, "1.1.1.1:443")
            && group_key(1, "1.1.1.1:443") != group_key(1, "1.1.1.1:80"),
        String::new(),
    );

    // 3. IPv6 rendering, incl. scope id and v4-mapped peers.
    //    Ports are given exactly as the MIB row does: network order in the low u16.
    //    (This check is why the raw-order contract is now written down: an earlier
    //    version of these assertions passed host-order ports and failed.)
    let net = |p: u16| u32::from(p.to_be());
    check(
        "v6: loopback without scope",
        v6_endpoint(Ipv6Addr::LOCALHOST, 0, net(443)) == "[::1]:443",
        v6_endpoint(Ipv6Addr::LOCALHOST, 0, net(443)),
    );
    let link_local: Ipv6Addr = "fe80::1234".parse().unwrap();
    check(
        "v6: link-local keeps its scope id",
        v6_endpoint(link_local, 7, net(80)) == "[fe80::1234%7]:80",
        v6_endpoint(link_local, 7, net(80)),
    );
    let mapped: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
    check(
        "v6: v4-mapped peer renders unchanged (no byte swap)",
        v6_endpoint(mapped, 0, net(8080)) == "[::ffff:127.0.0.1]:8080",
        v6_endpoint(mapped, 0, net(8080)),
    );
    check(
        "v6: port byte order is swapped exactly once",
        v6_endpoint(Ipv6Addr::LOCALHOST, 0, net(18483)) == "[::1]:18483"
            && v6_endpoint(Ipv6Addr::LOCALHOST, 0, net(18483)) != "[::1]:13128",
        v6_endpoint(Ipv6Addr::LOCALHOST, 0, net(18483)),
    );

    // 4. loopback classification (the filter's whole basis)
    let g: Ipv6Addr = "::ffff:8.8.8.8".parse().unwrap();
    check(
        "loopback: ::1 and ::ffff:127.0.0.1 are loopback",
        is_loopback_peer_v6(Ipv6Addr::LOCALHOST) && is_loopback_peer_v6(mapped),
        format!(
            "{}/{}",
            is_loopback_peer_v6(Ipv6Addr::LOCALHOST),
            is_loopback_peer_v6(mapped)
        ),
    );
    check(
        "loopback: ::ffff:8.8.8.8 and fe80:: are not",
        !is_loopback_peer_v6(g) && !is_loopback_peer_v6(link_local),
        format!(
            "{}/{}",
            is_loopback_peer_v6(g),
            is_loopback_peer_v6(link_local)
        ),
    );
    check(
        "loopback: v4 classification",
        Ipv4Addr::new(127, 0, 0, 1).is_loopback() && !Ipv4Addr::new(128, 0, 0, 1).is_loopback(),
        String::new(),
    );

    out
}

/// How many local endpoints a group carries before it starts summarising.
pub const LOCAL_SAMPLE: usize = 6;

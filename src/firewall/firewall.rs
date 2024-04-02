use ipnet::{self, IpNet};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        atomic::{AtomicBool, AtomicU16, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
};

use crate::{
    crypto::{
        core::hash_sha256,
        pki::{N3tworkCa, N3tworkCertificate},
    },
    error::{FirewallError, N3tworkError},
    net_types::{Protocol, TrafficDirection},
    timer::TimerWheel,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FirewallPacket {
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub local_port: i32,
    pub remote_port: i32,
    pub protocol: Protocol,
    pub fragment: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FirewallConntrackEntry {
    pub expires: Instant,
    pub sent: Instant,
    pub seq: u32,
    pub direction: TrafficDirection,
    pub rules_version: u16,
}

pub struct FirewallConntrack {
    pub conns: BTreeMap<FirewallPacket, FirewallConntrackEntry>,
    pub timer: TimerWheel<FirewallPacket>,
}

#[derive(Debug, Clone, Default)]
pub struct FirewallRule {
    pub any: bool,
    pub hosts: HashSet<String>,
    pub groups: HashSet<String>,
    pub ip: HashSet<IpNet>,
    pub local_ip: HashSet<IpNet>,
}

#[derive(Debug, Clone, Default)]
pub struct FirewallCA {
    any: FirewallRule,
    ca_names: HashMap<String, FirewallRule>,
    ca_shas: HashMap<String, FirewallRule>,
}

type FirewallPort = HashMap<i32, FirewallCA>;

#[derive(Debug, Clone, Default)]
pub struct FirewallTable {
    pub any: FirewallPort,
    pub tcp: FirewallPort,
    pub udp: FirewallPort,
    pub icmp: FirewallPort,
}

pub struct Firewall {
    pub conntrack: Arc<Mutex<FirewallConntrack>>,
    pub inbound_rules: Arc<RwLock<FirewallTable>>,
    pub outbound_rules: Arc<RwLock<FirewallTable>>,
    pub tcp_timeout: Duration,
    pub udp_timeout: Duration,
    pub default_timeout: Duration,
    pub local_ips: HashSet<IpNet>,
    pub rules: String,
    pub rules_version: AtomicU16,
    pub enabled: AtomicBool,
}

#[inline(always)]
fn check_ip_any(ip: IpNet) -> bool {
    const ANYV4: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    const ANYV6: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
    let net = ip.network();
    net == ANYV4 || net == ANYV6
}

impl FirewallPacket {
    pub fn new(
        local_ip: IpAddr,
        remote_ip: IpAddr,
        local_port: i32,
        remote_port: i32,
        protocol: Protocol,
        fragment: bool,
    ) -> Self {
        Self {
            local_ip,
            remote_ip,
            local_port,
            remote_port,
            protocol,
            fragment,
        }
    }
}

impl FirewallConntrackEntry {
    pub fn new(
        direction: TrafficDirection,
        seq: u32,
        expires: Instant,
        sent: Instant,
        rules_version: u16,
    ) -> Self {
        Self {
            direction,
            seq,
            expires,
            sent,
            rules_version,
        }
    }
}

impl FirewallConntrack {
    pub fn new(min: Duration, max: Duration) -> Self {
        let timer = TimerWheel::new(min, max);
        let conns = BTreeMap::new();
        Self { conns, timer }
    }

    pub fn add_conn(
        &mut self,
        packet: FirewallPacket,
        direction: TrafficDirection,
        timeout: Duration,
        rules_version: u16,
    ) -> Result<(), N3tworkError> {
        let now = Instant::now();
        if !self.conns.contains_key(&packet) {
            self.timer.advance(now);
            self.timer.add(packet.clone(), timeout);
        }
        let entry = FirewallConntrackEntry::new(direction, 0, now + timeout, now, rules_version);
        self.conns.insert(packet, entry);
        Ok(())
    }

    /// Checks if entry is expired
    /// if expired removes and returns entry
    /// if not re adds it to timer wheel and returns None
    pub fn evict(&mut self, packet: &FirewallPacket) -> Option<FirewallConntrackEntry> {
        if !self.conns.contains_key(packet) {
            return None;
        }

        let now = Instant::now();
        if self.conns[packet].expires > now {
            self.timer.advance(now);
            let new_t = self.conns[&packet].expires - now;
            self.timer.add(packet.clone(), new_t);
            return None;
        }

        self.conns.remove(&packet)
    }
}

impl FirewallRule {
    pub fn new(
        any: bool,
        hosts: HashSet<String>,
        groups: HashSet<String>,
        ip: HashSet<IpNet>,
        local_ip: HashSet<IpNet>,
    ) -> Self {
        Self {
            any,
            hosts,
            groups,
            ip,
            local_ip,
        }
    }
    pub fn new_any() -> Self {
        Self {
            any: true,
            hosts: Default::default(),
            groups: Default::default(),
            ip: Default::default(),
            local_ip: Default::default(),
        }
    }

    pub fn add_rule(
        &mut self,
        groups: &[String],
        hosts: &[String],
        ip: Option<IpNet>,
        local_ip: Option<IpNet>,
    ) -> Result<(), N3tworkError> {
        if self.any {
            return Ok(());
        }
        if FirewallRule::is_any(groups, hosts, ip, local_ip) {
            self.any = true;
            self.groups = Default::default();
            self.hosts = Default::default();
            self.ip = Default::default();
            self.local_ip = Default::default();
            return Ok(());
        }
        if groups.len() > 0 {
            self.groups.extend(groups.iter().cloned());
        }
        if hosts.len() > 0 {
            self.hosts.extend(hosts.iter().cloned());
        }
        if let Some(ip) = ip {
            self.ip.insert(ip);
        }
        if let Some(local_ip) = local_ip {
            self.local_ip.insert(local_ip);
        }

        Ok(())
    }

    #[inline(always)]
    pub fn is_any(
        groups: &[String],
        host: &[String],
        ip: Option<IpNet>,
        local_ip: Option<IpNet>,
    ) -> bool {
        if groups.len() == 0 && host.len() == 0 && ip.is_none() && local_ip.is_none() {
            return true;
        }

        if groups.iter().any(|g| g == "*" || g == "any") {
            return true;
        }
        if host.iter().any(|h| h == "*" || h == "any") {
            return true;
        }

        if let Some(ip) = ip {
            if check_ip_any(ip) {
                return true;
            }
        }

        if let Some(local_ip) = local_ip {
            if check_ip_any(local_ip) {
                return true;
            }
        }
        false
    }

    /// returns true if any, or if one of the groups, hosts, ip, or local_ip match
    pub fn matches(&self, packet: &FirewallPacket, cert: &N3tworkCertificate) -> bool {
        if self.any {
            return true;
        }
        if self.groups.len() > 0 {
            if cert.metadata.groups.iter().any(|g| self.groups.contains(g)) {
                return true;
            }
        }
        if self.hosts.len() > 0 {
            if self.hosts.contains(&cert.metadata.name) {
                return true;
            }
        }

        if self.ip.contains(&IpNet::from(packet.remote_ip))
            || self.local_ip.contains(&IpNet::from(packet.local_ip))
        {
            return true;
        }
        false
    }
}

impl FirewallCA {
    pub fn add_rule(
        &mut self,
        groups: &[String],
        hosts: &[String],
        ip: Option<IpNet>,
        local_ip: Option<IpNet>,
        ca_name: String,
        ca_sha: String,
    ) -> Result<(), N3tworkError> {
        if groups.len() == 0 && hosts.len() == 0 && ip.is_none() && local_ip.is_none() {
            return self.any.add_rule(groups, hosts, ip, local_ip);
        }

        if ca_name.len() == 0 && ca_sha.len() == 0 {
            return self.any.add_rule(groups, hosts, ip, local_ip);
        }
        if ca_sha.len() > 0 {
            self.ca_shas
                .entry(ca_sha)
                .and_modify(|ca| {
                    if let Err(e) = ca.add_rule(groups, hosts, ip, local_ip) {
                        tracing::error!("{:?}", e);
                    }
                })
                .or_insert({
                    let mut ca = FirewallRule::default();
                    if let Err(e) = ca.add_rule(groups, hosts, ip, local_ip) {
                        tracing::error!("{:?}", e);
                    }
                    ca
                });
        }
        if ca_name.len() > 0 {
            self.ca_names
                .entry(ca_name)
                .and_modify(|ca| {
                    if let Err(e) = ca.add_rule(groups, hosts, ip, local_ip) {
                        tracing::error!("{:?}", e);
                    }
                })
                .or_insert({
                    let mut ca = FirewallRule::default();
                    if let Err(e) = ca.add_rule(groups, hosts, ip, local_ip) {
                        tracing::error!("{:?}", e);
                    }
                    ca
                });
        }
        Ok(())
    }

    pub fn matches(
        &self,
        packet: &FirewallPacket,
        cert: &N3tworkCertificate,
        ca: &N3tworkCa,
    ) -> bool {
        if self.any.matches(&packet, &cert) {
            return true;
        }

        if let Some(ca) = self.ca_shas.get(&cert.metadata.issuer) {
            if ca.matches(&packet, &cert) {
                return true;
            }
        }
        if let Some(s) = ca.ca.get(&cert.metadata.issuer) {
            if let Some(rule) = self.ca_names.get(&s.metadata.name) {
                if rule.matches(&packet, &cert) {
                    return true;
                }
            }
        }

        false
    }
}

impl FirewallTable {
    fn add_all(
        m: &mut FirewallPort,
        i: i32,
        groups: &[String],
        hosts: &[String],
        ip: Option<IpNet>,
        local_ip: Option<IpNet>,
        ca_name: String,
        ca_sha: String,
    ) {
        m.entry(i)
            .and_modify(|ca| {
                if let Err(e) =
                    ca.add_rule(groups, hosts, ip, local_ip, ca_name.clone(), ca_sha.clone())
                {
                    tracing::error!("{:?}", e);
                }
            })
            .or_insert({
                let mut ca = FirewallCA::default();
                if let Err(e) =
                    ca.add_rule(groups, hosts, ip, local_ip, ca_name.clone(), ca_sha.clone())
                {
                    tracing::error!("{:?}", e);
                }
                ca
            });
    }

    #[tracing::instrument(name = "firewall table add rule", skip(self))]
    pub fn add_rule(
        &mut self,
        proto: Protocol,
        start_port: i32,
        end_port: i32,
        groups: &[String],
        hosts: &[String],
        ip: Option<IpNet>,
        local_ip: Option<IpNet>,
        ca_name: String,
        ca_sha: String,
    ) -> Result<(), FirewallError> {
        if start_port > end_port {
            let msg = format!(
                "start port {} is greater than end port {}",
                start_port, end_port
            );
            tracing::error!("{:?}", msg);
            return Err(FirewallError::InvalidPortRange(msg));
        }
        let mut end_port = end_port;
        if start_port == 0 && end_port == 0 {
            end_port = u16::MAX as i32;
        }
        match proto {
            Protocol::ANY => (start_port..=end_port).for_each(|i| {
                FirewallTable::add_all(
                    &mut self.any,
                    i,
                    groups,
                    hosts,
                    ip,
                    local_ip,
                    ca_name.clone(),
                    ca_sha.clone(),
                );
            }),
            Protocol::TCP => (start_port..=end_port).for_each(|i| {
                FirewallTable::add_all(
                    &mut self.tcp,
                    i,
                    groups,
                    hosts,
                    ip,
                    local_ip,
                    ca_name.clone(),
                    ca_sha.clone(),
                );
            }),
            Protocol::UDP => (start_port..=end_port).for_each(|i| {
                FirewallTable::add_all(
                    &mut self.udp,
                    i,
                    groups,
                    hosts,
                    ip,
                    local_ip,
                    ca_name.clone(),
                    ca_sha.clone(),
                );
            }),
            Protocol::ICMP => (start_port..=end_port).for_each(|i| {
                FirewallTable::add_all(
                    &mut self.icmp,
                    i,
                    groups,
                    hosts,
                    ip,
                    local_ip,
                    ca_name.clone(),
                    ca_sha.clone(),
                );
            }),
        }

        Ok(())
    }

    pub fn matches(
        &self,
        packet: &FirewallPacket,
        cert: &N3tworkCertificate,
        direction: TrafficDirection,
        ca: &N3tworkCa,
    ) -> bool {
        let port = if packet.fragment {
            todo!()
        } else {
            match direction {
                TrafficDirection::Incoming => packet.local_port,
                TrafficDirection::Outgoing => packet.remote_port,
            }
        };

        if let Some(fca) = self.any.get(&port) {
            if fca.matches(packet, cert, ca) {
                return true;
            }
        }
        match packet.protocol {
            Protocol::TCP => {
                if let Some(fca) = self.tcp.get(&port) {
                    if fca.matches(packet, cert, ca) {
                        return true;
                    }
                }
            }
            Protocol::UDP => {
                if let Some(fca) = self.udp.get(&port) {
                    if fca.matches(packet, cert, ca) {
                        return true;
                    }
                }
            }
            Protocol::ICMP => {
                if let Some(fca) = self.icmp.get(&port) {
                    if fca.matches(packet, cert, ca) {
                        return true;
                    }
                }
            }
            _ => {}
        }
        false
    }
}

impl Firewall {
    pub fn new(
        tcp_timeout: Duration,
        udp_timeout: Duration,
        default_timeout: Duration,
        cert: N3tworkCertificate,
    ) -> Self {
        let mut min = tcp_timeout;
        let mut max = udp_timeout;
        if min > max {
            std::mem::swap(&mut min, &mut max);
        }
        if default_timeout < min {
            min = default_timeout;
        } else if default_timeout > max {
            max = default_timeout;
        }
        let conntrack = Arc::new(Mutex::new(FirewallConntrack::new(min, max)));
        let inbound_rules = Arc::new(RwLock::new(FirewallTable::default()));
        let outbound_rules = Arc::new(RwLock::new(FirewallTable::default()));
        let rules = String::new();
        let mut local_ips = cert.metadata.ips.clone();

        for subnet in cert.metadata.subnets.iter() {
            local_ips.extend(subnet.collect::<Vec<IpNet>>());
        }

        Self {
            conntrack,
            inbound_rules,
            outbound_rules,
            tcp_timeout,
            udp_timeout,
            default_timeout,
            local_ips,
            rules,
            rules_version: AtomicU16::new(0),
            enabled: AtomicBool::new(true),
        }
    }

    pub fn add_rule(
        &mut self,
        direction: TrafficDirection,
        proto: Protocol,
        start_port: i32,
        end_port: i32,
        groups: Vec<String>,
        hosts: Vec<String>,
        ip: Option<IpNet>,
        local_ip: Option<IpNet>,
        ca_name: String,
        ca_sha: String,
    ) -> Result<(), FirewallError> {
        let rule_string = format!("incoming: {:?}, proto: {:?}, startPort: {:?}, endPort: {:?}, groups: {:?}, host: {:?}, ip: {:?}, localIp: {:?}, ca_name: {:?}, ca_sha: {:?}", direction, proto, start_port, end_port, groups, hosts, ip, local_ip, ca_name, ca_sha);
        self.rules = format!("{}{}\n", self.rules, rule_string);
        match direction {
            TrafficDirection::Incoming => self.inbound_rules.write().unwrap().add_rule(
                proto, start_port, end_port, &*groups, &*hosts, ip, local_ip, ca_name, ca_sha,
            ),
            TrafficDirection::Outgoing => self.outbound_rules.write().unwrap().add_rule(
                proto, start_port, end_port, &*groups, &*hosts, ip, local_ip, ca_name, ca_sha,
            ),
        }
    }

    pub fn evict(&mut self, packet: &FirewallPacket) -> Option<FirewallConntrackEntry> {
        self.conntrack.lock().unwrap().evict(&packet)
    }

    pub fn toggle_enabled(&self) {
        //TODO
        self.enabled.fetch_xor(true, Ordering::SeqCst);
    }

    pub fn hash_rule(&self) -> [u8; 32] {
        hash_sha256(self.rules.as_bytes())
    }

    pub fn add_conn(
        &mut self,
        packet: FirewallPacket,
        direction: TrafficDirection,
    ) -> Result<(), N3tworkError> {
        let timeout = match packet.protocol {
            Protocol::TCP => self.tcp_timeout,
            Protocol::UDP => self.udp_timeout,
            _ => self.default_timeout,
        };
        self.conntrack.lock().unwrap().add_conn(
            packet,
            direction,
            timeout,
            self.rules_version.load(Ordering::SeqCst),
        )
    }

    pub fn in_conns(&mut self, packet: &FirewallPacket) -> bool {
        let mut conntrack = self.conntrack.lock().unwrap();
        if let Some(p) = conntrack.timer.purge() {
            _ = conntrack.evict(&p);
        }
        if !conntrack.conns.contains_key(packet) {
            return false;
        }
        if let Some(conn) = conntrack.conns.get_mut(packet) {
            if conn.rules_version != self.rules_version.load(Ordering::SeqCst) {
                todo!("check rules, validate old version is compatible with new version");
            }
            conn.expires = match packet.protocol {
                Protocol::TCP => Instant::now() + self.tcp_timeout,
                Protocol::UDP => Instant::now() + self.udp_timeout,
                _ => Instant::now() + self.default_timeout,
            };
        } else {
            return false;
        }

        true
    }

    /// returns Ok if the packet is allowed and Err if packet should be dropped
    fn drop_conn(
        &mut self,
        packet: &FirewallPacket,
        direction: TrafficDirection,
        cert: &N3tworkCertificate,
        ca: &N3tworkCa,
    ) -> Result<(), N3tworkError> {
        if self.in_conns(packet) {
            return Ok(());
        }

        if !cert.metadata.ips.contains(&IpNet::from(packet.remote_ip)) {
            return Err(N3tworkError::InvalidAddress(
                "invalid packet remote ip".to_string(),
            ));
        }

        if !self.local_ips.contains(&IpNet::from(packet.local_ip)) {
            return Err(N3tworkError::InvalidAddress(
                "invalid packet local ip".to_string(),
            ));
        }

        match direction {
            TrafficDirection::Incoming => {
                if !self
                    .inbound_rules
                    .read()
                    .unwrap()
                    .matches(&packet, &cert, direction, ca)
                {
                    return Err(N3tworkError::InvalidAddress("no matching rule".to_string()));
                }
            }
            TrafficDirection::Outgoing => {
                if !self
                    .outbound_rules
                    .read()
                    .unwrap()
                    .matches(&packet, &cert, direction, ca)
                {
                    return Err(N3tworkError::InvalidAddress("no matching rule".to_string()));
                }
            }
        }

        self.add_conn(packet.clone(), direction)
    }

    pub fn reset_conntrack(&mut self) {
        self.conntrack.lock().unwrap().conns = BTreeMap::default();
    }
}

#[cfg(test)]
mod test_firewall {

    use super::*;
    use chrono::{DateTime, Months, Utc};

    #[test]
    fn test_is_any() {
        let ip_is_true: Vec<Option<IpNet>> = vec![
            Some("::/0".parse().unwrap()),
            Some("0.0.0.0/0".parse().unwrap()),
            None,
        ];
        let ip_is_false: Vec<Option<IpNet>> = vec![
            Some("127.0.0.1/8".parse().unwrap()),
            Some(
                "8278:7e24:f450:cd29:0895:0fa6:d7e0:c33a/32"
                    .parse()
                    .unwrap(),
            ),
            Some(
                "35a9:a90c:3869:85d9:4e1b:420c:fafe:72cf/32"
                    .parse()
                    .unwrap(),
            ),
        ];
        let groups_is_true = vec!["*", "any"];
        let groups_is_false = vec!["group1", "group2"];
        let host_is_true = vec!["*", "any"];
        let host_is_false = vec!["host1", "host2"];

        for ip in ip_is_true.clone() {
            for groups in groups_is_true.iter() {
                for host in host_is_true.iter() {
                    let k =
                        FirewallRule::is_any(&[groups.to_string()], &[host.to_string()], ip, ip);
                    assert_eq!(k, true);
                }
            }
        }

        for ip in ip_is_false {
            for groups in groups_is_false.iter() {
                for host in host_is_false.iter() {
                    let k =
                        FirewallRule::is_any(&[groups.to_string()], &[host.to_string()], ip, ip);
                    assert_eq!(k, false);
                }
            }
        }
    }

    #[test]
    fn test_add_rule_tcp() {
        let mut local_ips = HashSet::new();
        local_ips.insert("1.2.3.4/32".parse().unwrap());
        let mut cert = N3tworkCertificate::default();
        cert.metadata.ips = local_ips.clone();
        let mut firewall = Firewall::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            Duration::from_secs(60 * 3),
            cert,
        );
        let val = firewall.add_rule(
            TrafficDirection::Incoming,
            Protocol::TCP,
            1,
            1,
            vec![],
            vec![],
            None,
            None,
            "".to_string(),
            "".to_string(),
        );
        assert!(val.is_ok());
        assert!(firewall.inbound_rules.read().unwrap().tcp.contains_key(&1));
        let guard = firewall.inbound_rules.read().unwrap();

        let val = guard.tcp.get(&1).unwrap();
        assert!(val.any.any);
        assert!(val.any.hosts.is_empty());
        assert!(val.any.groups.is_empty());
    }

    #[test]
    fn test_add_rule_udp() {
        let mut local_ips = HashSet::new();
        local_ips.insert("1.2.3.4/32".parse().unwrap());
        let mut cert = N3tworkCertificate::default();
        cert.metadata.ips = local_ips.clone();

        let mut firewall = Firewall::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            Duration::from_secs(60 * 60),
            cert,
        );

        let val = firewall.add_rule(
            TrafficDirection::Incoming,
            Protocol::UDP,
            1,
            1,
            vec!["g1".into()],
            vec![],
            None,
            None,
            "".to_string(),
            "".to_string(),
        );
        assert!(val.is_ok());
        {
            let guard = firewall.inbound_rules.read().unwrap();
            let val = guard.udp.get(&1).unwrap();
            assert!(!val.any.any);
            assert!(val.any.hosts.is_empty());
            assert!(val.any.groups.contains("g1"));
        }

        let val = firewall.add_rule(
            TrafficDirection::Incoming,
            Protocol::UDP,
            1,
            1,
            vec!["g1".into()],
            vec![],
            None,
            None,
            "has-name".to_string(),
            "".to_string(),
        );
        assert!(val.is_ok());
        {
            let guard = firewall.inbound_rules.read().unwrap();
            let val = guard.udp.get(&1);
            assert!(val.is_some());
            let val = val.unwrap();
            assert!(val.ca_names.contains_key("has-name"));
        }

        let val = firewall.add_rule(
            TrafficDirection::Incoming,
            Protocol::UDP,
            1,
            1,
            vec!["g1".into()],
            vec![],
            None,
            None,
            "".to_string(),
            "has-sha".to_string(),
        );
        assert!(val.is_ok());
        {
            let guard = firewall.inbound_rules.read().unwrap();
            let val = guard.udp.get(&1);
            assert!(val.is_some());
            let val = val.unwrap();
            assert!(val.ca_shas.contains_key("has-sha"));
        };
    }

    #[test]
    fn test_add_rule_icmp() {
        let mut local_ips = HashSet::new();
        local_ips.insert("1.2.3.4/32".parse().unwrap());
        let mut cert = N3tworkCertificate::default();
        cert.metadata.ips = local_ips.clone();
        let mut firewall = Firewall::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            Duration::from_secs(60 * 60),
            cert,
        );

        let val = firewall.add_rule(
            TrafficDirection::Incoming,
            Protocol::ICMP,
            1,
            1,
            vec![],
            vec!["h1".into()],
            None,
            None,
            "".to_string(),
            "".to_string(),
        );

        assert!(val.is_ok());
        let guard = firewall.inbound_rules.read().unwrap();
        let val = guard.icmp.get(&1).unwrap();
        assert!(!val.any.any);
        assert!(val.any.hosts.contains("h1"));
        assert!(val.any.groups.is_empty());
    }

    #[test]
    fn test_add_rule_any() {
        let mut local_ips = HashSet::new();
        local_ips.insert("1.2.3.4/32".parse().unwrap());
        let mut cert = N3tworkCertificate::default();
        cert.metadata.ips = local_ips.clone();
        let mut firewall = Firewall::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            Duration::from_secs(60 * 60),
            cert.clone(),
        );

        let local_net: IpNet = "1.2.3.4/32".parse().unwrap();
        let val = firewall.add_rule(
            TrafficDirection::Incoming,
            Protocol::ANY,
            1,
            1,
            vec![],
            vec![],
            None,
            Some(local_net.clone()),
            "".to_string(),
            "".to_string(),
        );

        assert!(val.is_ok());
        {
            let guard = firewall.inbound_rules.read().unwrap();
            let val = guard.any.get(&1).unwrap();
            assert!(!val.any.any);
            assert!(val.any.hosts.is_empty());
            assert!(val.any.groups.is_empty());
            assert!(val.any.local_ip.contains(&local_net));
        }
        let mut firewall = Firewall::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            Duration::from_secs(60 * 60),
            cert.clone(),
        );

        let val = firewall.add_rule(
            TrafficDirection::Incoming,
            Protocol::ANY,
            0,
            0,
            vec!["any".into()],
            vec!["any".into()],
            None,
            None,
            "".to_string(),
            "".to_string(),
        );
        assert!(val.is_ok());
        {
            let guard = firewall.inbound_rules.read().unwrap();
            let val = guard.any.get(&0).unwrap();
            assert!(val.any.any);
            assert!(val.any.hosts.is_empty());
            assert!(val.any.groups.is_empty());
        }

        let mut firewall = Firewall::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            Duration::from_secs(60 * 60),
            cert,
        );

        let val = firewall.add_rule(
            TrafficDirection::Incoming,
            Protocol::ANY,
            0,
            0,
            vec![],
            vec![],
            Some("::/0".parse().unwrap()),
            None,
            "".to_string(),
            "".to_string(),
        );
        assert!(val.is_ok());

        {
            let guard = firewall.inbound_rules.read().unwrap();
            let val = guard.any.get(&0).unwrap();
            assert!(val.any.any);
        }
    }

    #[test]
    fn test_add_evict_conn() {
        let mut local_ips = HashSet::new();
        local_ips.insert("1.2.3.4/28".parse().unwrap());
        let mut cert = N3tworkCertificate::default();
        cert.metadata.ips = local_ips.clone();
        let mut firewall = Firewall::new(
            Duration::from_secs(1),
            Duration::from_secs(10),
            Duration::from_secs(10),
            cert,
        );

        let packet = FirewallPacket::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 6)),
            80,
            80,
            Protocol::TCP,
            false,
        );

        assert!(firewall
            .add_conn(packet.clone(), TrafficDirection::Incoming)
            .is_ok());
        assert!(firewall.evict(&packet).is_none());
        std::thread::sleep(Duration::from_secs(2));
        assert!(firewall.evict(&packet).is_some());
    }

    #[test]
    fn test_in_conns() {
        let mut local_ips = HashSet::new();
        local_ips.insert("1.2.3.4/28".parse().unwrap());
        let mut cert = N3tworkCertificate::default();
        cert.metadata.ips = local_ips.clone();
        let mut firewall = Firewall::new(
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(2),
            cert,
        );

        let p1 = FirewallPacket::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 6)),
            80,
            80,
            Protocol::TCP,
            false,
        );

        assert!(firewall
            .add_conn(p1.clone(), TrafficDirection::Incoming)
            .is_ok());
        assert!(firewall.in_conns(&p1));
        let mut p2 = p1.clone();
        p2.local_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 7));
        assert!(!firewall.in_conns(&p2));
        std::thread::sleep(Duration::from_secs(2));
        assert!(firewall
            .add_conn(p2.clone(), TrafficDirection::Incoming)
            .is_ok());
        assert!(!firewall.in_conns(&p1))
    }

    #[test]
    fn test_firewall_times() {
        let mut local_ips = HashSet::new();
        local_ips.insert("1.2.3.4/32".parse().unwrap());
        let second = Duration::from_secs(1);
        let minute = Duration::from_secs(60);
        let hour = Duration::from_secs(60 * 60);
        let mut cert = N3tworkCertificate::default();
        cert.metadata.ips = local_ips.clone();
        let firewall = Firewall::new(second, minute, hour, cert.clone());
        assert_eq!(second, firewall.tcp_timeout);
        assert_eq!(minute, firewall.udp_timeout);
        assert_eq!(hour, firewall.default_timeout);

        let conntrack = firewall.conntrack.lock().unwrap();
        assert_eq!(hour, conntrack.timer.wheel_duration);
        assert_eq!(3602, conntrack.timer.wheel_len);
    }

    const TEST_LOCAL_NET: &str = "1.2.3.4/32";
    const TEST_LOCAL_ADDR: &str = "1.2.3.4";

    fn make_test_cert() -> N3tworkCertificate {
        let mut cert = N3tworkCertificate::read_from_file("test/certs/RootCA.pem")
            .expect("failed to read cert")[0]
            .clone();
        cert.metadata.not_before = DateTime::from(Utc::now())
            .checked_sub_months(Months::new(1))
            .unwrap();
        cert.metadata.not_after = DateTime::from(Utc::now())
            .checked_add_months(Months::new(1))
            .unwrap();
        cert.metadata.ips.insert(TEST_LOCAL_NET.parse().unwrap());
        cert.metadata
            .ips
            .insert(IpNet::from(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        cert.metadata.groups.insert("default_group".to_string());
        cert.metadata.issuer = "signer-shasum".to_string();
        cert.metadata.name = "host1".into();
        cert
    }

    #[test]
    fn test_firewall_table_matches() {
        let net: IpNet = "172.1.1.1/32".parse().unwrap();
        let addr = "172.1.1.1".parse().unwrap();
        let mut table = FirewallTable::default();
        let proto = Protocol::TCP;
        let ca = N3tworkCa::default();
        table
            .add_rule(
                proto,
                10,
                10,
                &*vec!["group1".into()],
                &*vec!["host1".into()],
                Some(net),
                Some(net),
                "".into(),
                "".into(),
            )
            .unwrap();
        table
            .add_rule(
                proto,
                10,
                10,
                &*vec!["group2".into()],
                &*vec!["host1".into()],
                Some(net),
                Some(net),
                "".into(),
                "".into(),
            )
            .unwrap();
        table
            .add_rule(
                proto,
                10,
                10,
                &*vec!["group3".into()],
                &*vec!["host1".into()],
                Some(net),
                Some(net),
                "".into(),
                "".into(),
            )
            .unwrap();
        table
            .add_rule(
                proto,
                10,
                10,
                &*vec!["group4".into()],
                &*vec!["host1".into()],
                Some(net),
                Some(net),
                "".into(),
                "".into(),
            )
            .unwrap();
        table
            .add_rule(
                proto,
                10,
                10,
                &*vec!["group5".into(), "group6".into()],
                &*vec!["host1".into()],
                Some(net),
                Some(net),
                "".into(),
                "".into(),
            )
            .unwrap();

        let good_cert = || {
            let mut cert = N3tworkCertificate::default();
            cert.metadata.ips.insert(net);
            for group in vec!["group1", "group2", "group3", "group4", "group5", "group6"] {
                cert.metadata.groups.insert(group.into());
            }
            cert.metadata.not_after = chrono::DateTime::from(Utc::now())
                .checked_add_months(Months::new(1))
                .unwrap();
            cert.metadata.not_before = chrono::DateTime::from(Utc::now())
                .checked_sub_months(Months::new(1))
                .unwrap();
            cert.metadata.is_ca = true;
            cert
        };
        let direction = TrafficDirection::Incoming;
        let mut packet = FirewallPacket::new(addr, addr, 10, 10, Protocol::TCP, false);
        let cert = good_cert();
        assert!(table.matches(&packet, &cert, direction, &ca));
        packet.protocol = Protocol::UDP;
        assert!(!table.matches(&packet, &cert, direction, &ca));
        packet.protocol = Protocol::TCP;
        packet.local_port = 11;
        assert!(!table.matches(&packet, &cert, direction, &ca));
        packet.local_port = 10;
        let mut cert = good_cert();
        cert.metadata.groups.clear();
        assert!(table.matches(&packet, &cert, direction, &ca));
        cert.metadata.name = "host1".to_string();
        // test name
        cert.metadata.groups.clear();
        assert!(table.matches(&packet, &cert, direction, &ca));
    }

    #[test]
    fn test_drop_conn() {
        let cert = make_test_cert();
        let local_addr = TEST_LOCAL_ADDR.parse().unwrap();
        let remote_addr = TEST_LOCAL_ADDR.parse().unwrap();
        let ca = N3tworkCa::default();
        let local_port = 10;
        let remote_port = 80;
        let protocol = Protocol::UDP;
        let fragment = false;
        let direction = TrafficDirection::Incoming;
        let opposite_direction = TrafficDirection::Outgoing;
        let mut packet = FirewallPacket::new(
            local_addr,
            remote_addr,
            local_port,
            remote_port,
            protocol,
            fragment,
        );

        let mut firewall = Firewall::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            Duration::from_secs(60 * 60),
            cert.clone(),
        );
        let _ = firewall.add_rule(
            TrafficDirection::Incoming,
            Protocol::ANY,
            0,
            0,
            vec!["any".into()],
            vec![],
            None,
            None,
            "".to_string(),
            "".to_string(),
        );

        assert!(firewall
            .drop_conn(&packet, opposite_direction, &cert, &ca)
            .is_err());
        firewall.reset_conntrack();
        assert!(firewall.drop_conn(&packet, direction, &cert, &ca).is_ok());
        assert!(firewall
            .drop_conn(&packet, opposite_direction, &cert, &ca)
            .is_ok());
        packet.remote_ip = "1.2.3.10".parse().unwrap();
        assert!(firewall.drop_conn(&packet, direction, &cert, &ca).is_err());
        packet.remote_ip = remote_addr;
    }

    #[test]
    fn test_signer_drop() {
        let cert = make_test_cert();
        let ca = N3tworkCa::default();
        let mut firewall = Firewall::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            Duration::from_secs(60 * 60),
            cert.clone(),
        );
        let direction = TrafficDirection::Incoming;
        let proto = Protocol::ANY;

        let packet = FirewallPacket::new(
            TEST_LOCAL_ADDR.parse().unwrap(),
            TEST_LOCAL_ADDR.parse().unwrap(),
            10,
            90,
            proto,
            false,
        );

        let _ = firewall.add_rule(
            direction,
            proto,
            0,
            0,
            vec!["bad".into()],
            vec![],
            None,
            None,
            "".into(),
            "signer-shasum".into(),
        );
        let _ = firewall.add_rule(
            direction,
            proto,
            0,
            0,
            vec!["default_group".into()],
            vec![],
            None,
            None,
            "".into(),
            "signer-shasum-bad".into(),
        );
        assert!(firewall.drop_conn(&packet, direction, &cert, &ca).is_err());
        let mut firewall = Firewall::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            Duration::from_secs(60 * 60),
            cert.clone(),
        );

        let _ = firewall.add_rule(
            direction,
            proto,
            0,
            0,
            vec!["bad".into()],
            vec![],
            None,
            None,
            "".into(),
            "signer-shasum-bad".into(),
        );
        let _ = firewall.add_rule(
            direction,
            proto,
            0,
            0,
            vec!["default_group".into()],
            vec![],
            None,
            None,
            "".into(),
            "signer-shasum".into(),
        );
        assert!(firewall.drop_conn(&packet, direction, &cert, &ca).is_ok());
    }

    #[test]
    fn test_ca_sha_drop() {
        let cert = make_test_cert();
        let ca = N3tworkCa::default();
        let mut firewall = Firewall::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            Duration::from_secs(60 * 60),
            cert.clone(),
        );
        let direction = TrafficDirection::Incoming;
        let proto = Protocol::ANY;

        let packet = FirewallPacket::new(
            TEST_LOCAL_ADDR.parse().unwrap(),
            TEST_LOCAL_ADDR.parse().unwrap(),
            10,
            90,
            proto,
            false,
        );

        let _ = firewall.add_rule(
            direction,
            proto,
            0,
            0,
            vec!["bad".into()],
            vec![],
            None,
            None,
            "".into(),
            "signer-shasum-bad".into(),
        );
        let _ = firewall.add_rule(
            direction,
            proto,
            0,
            0,
            vec!["default_group".into()],
            vec![],
            None,
            None,
            "".into(),
            "signer-shasum".into(),
        );
        assert!(firewall.drop_conn(&packet, direction, &cert, &ca).is_ok());
    }

    #[test]
    fn test_ca_name_drop() {
        let cert = make_test_cert();
        let mut ca = N3tworkCa::default();
        let mut firewall = Firewall::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            Duration::from_secs(60 * 60),
            cert.clone(),
        );
        let direction = TrafficDirection::Incoming;
        let proto = Protocol::ANY;

        let packet = FirewallPacket::new(
            TEST_LOCAL_ADDR.parse().unwrap(),
            TEST_LOCAL_ADDR.parse().unwrap(),
            10,
            90,
            proto,
            false,
        );

        ca.ca.insert("signer-shasum".into(), cert.clone());
        let _ = firewall.add_rule(
            direction,
            proto,
            0,
            0,
            vec!["bad".into()],
            vec![],
            None,
            None,
            cert.metadata.name.clone().into(),
            "".into(),
        );
        let _ = firewall.add_rule(
            direction,
            proto,
            0,
            0,
            vec!["default_group".into()],
            vec![],
            None,
            None,
            "ca_name_bad".into(),
            "".into(),
        );
        assert!(firewall.drop_conn(&packet, direction, &cert, &ca).is_err());

        let mut firewall = Firewall::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            Duration::from_secs(60 * 60),
            cert.clone(),
        );

        let _ = firewall.add_rule(
            direction,
            proto,
            0,
            0,
            vec!["bad".into()],
            vec![],
            None,
            None,
            "ca_name_bad".into(),
            "".into(),
        );
        let _ = firewall.add_rule(
            direction,
            proto,
            0,
            0,
            vec!["default_group".into()],
            vec![],
            None,
            None,
            cert.metadata.name.clone().into(),
            "".into(),
        );
        assert!(firewall.drop_conn(&packet, direction, &cert, &ca).is_ok());
    }
}

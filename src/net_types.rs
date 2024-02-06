use serde::{Deserialize, Serialize};
use std::fmt;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TrafficDecision: u8 {
        const ALLOW  = 0b0000_0001;
        const DROP   = 0b0000_0010;
        const REJECT = 0b0000_0100;
        const LOG    = 0b0000_1000;
    }
}

/// traffic direction (incoming or outgoing).
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub enum TrafficDirection {
    Incoming,
    Outgoing,
}

impl Default for TrafficDirection {
    fn default() -> Self {
        Self::Incoming
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[allow(clippy::upper_case_acronyms)]
pub enum Protocol {
    ANY = 0,
    ICMP = 1,
    TCP = 6,
    UDP = 17,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<u8> for Protocol {
    fn from(p: u8) -> Self {
        match p {
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            1 => Protocol::ICMP,
            _ => Protocol::ANY,
        }
    }
}

impl Protocol {
    #[inline(always)]
    pub fn to_string(&self) -> String {
        match self {
            Protocol::TCP => "TCP".to_string(),
            Protocol::UDP => "UDP".to_string(),
            Protocol::ICMP => "ICMP".to_string(),
            Protocol::ANY => "ANY".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpScope {
    Invalid = -1,
    Undefined = 0,
    HostLocal = 1,
    LinkLocal = 2,
    SiteLocal = 3,
    Global = 4,
    LocalMulticast = 5,
    GlobalMulticast = 6,
}

impl From<std::net::Ipv4Addr> for IpScope {
    fn from(value: std::net::Ipv4Addr) -> Self {
        let octets = value.octets();
        match octets[0] {
            0 if octets[1] == 0 && octets[2] == 0 && octets[3] == 0 => IpScope::LocalMulticast,
            0 => IpScope::Invalid,
            10 => IpScope::SiteLocal,
            100 if octets[1] & 0b11000000 == 64 => IpScope::SiteLocal,
            127 => IpScope::HostLocal,
            169 if octets[1] == 254 => IpScope::LinkLocal,
            172 if octets[1] & 0b11110000 == 16 => IpScope::SiteLocal,
            192 if octets[1] == 0 && octets[2] == 2 => IpScope::Invalid,
            192 if octets[1] == 168 => IpScope::SiteLocal,
            198 if octets[1] == 51 && octets[2] == 100 => IpScope::Invalid,
            203 if octets[1] == 0 && octets[2] == 113 => IpScope::Invalid,
            224 => IpScope::LocalMulticast,
            233 if octets[1] == 252 && octets[2] == 0 => IpScope::Invalid,
            225..=238 => IpScope::GlobalMulticast,
            239 => IpScope::LocalMulticast,
            240..=254 => IpScope::Invalid,
            255 if octets[1] == 255 && octets[2] == 255 && octets[3] == 255 => {
                IpScope::LocalMulticast
            }
            _ => IpScope::Global,
        }
    }
}

impl From<std::net::Ipv6Addr> for IpScope {
    fn from(value: std::net::Ipv6Addr) -> Self {
        let octets = value.octets();
        if octets.iter().all(|&x| x == 0) {
            return IpScope::Invalid;
        }
        if value.is_loopback() {
            return IpScope::HostLocal;
        }
        // fc00::/7
        if octets[0] & 0xfe == 0xfc {
            return IpScope::SiteLocal;
        }

        match octets[0] {
            0 => IpScope::LocalMulticast,
            0xfe if octets[1] & 0xc0 == 0x80 => IpScope::LinkLocal, //fe80::/10
            0xff if octets[1] <= 0x05 => IpScope::LocalMulticast,   //ff00::/16 - ff05::/16
            0xff => IpScope::GlobalMulticast,
            _ => IpScope::Global,
        }
    }
}

#[cfg(test)]
mod test_net_types {
    use ipnet::IpNet;

    use super::*;
    #[test]
    fn test_ip_scope() {
        let to_ip4 = |a, b, c, d| std::net::Ipv4Addr::new(a, b, c, d);
        assert_eq!(IpScope::from(to_ip4(71, 87, 113, 211)), IpScope::Global);
        assert_eq!(IpScope::from(to_ip4(127, 0, 0, 1)), IpScope::HostLocal);
        assert_eq!(IpScope::from(to_ip4(127, 255, 255, 1)), IpScope::HostLocal);
        assert_eq!(IpScope::from(to_ip4(192, 168, 172, 24)), IpScope::SiteLocal);
        assert_eq!(IpScope::from(to_ip4(172, 15, 1, 1)), IpScope::Global);
        assert_eq!(IpScope::from(to_ip4(172, 16, 1, 1)), IpScope::SiteLocal);
        assert_eq!(IpScope::from(to_ip4(172, 31, 1, 1)), IpScope::SiteLocal);
        assert_eq!(IpScope::from(to_ip4(172, 32, 1, 1)), IpScope::Global);

        assert_eq!(
            IpScope::from(std::net::Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)),
            IpScope::LocalMulticast
        );
    }
}

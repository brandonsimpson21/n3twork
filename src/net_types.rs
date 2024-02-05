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

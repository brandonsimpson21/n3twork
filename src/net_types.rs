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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub enum Protocol {
    ANY,
    TCP,
    UDP,
    ICMP,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

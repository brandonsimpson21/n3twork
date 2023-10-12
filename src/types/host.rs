pub mod host {
    use crate::types::{asn::asn::Asn, country::countries::Country};


    /// Struct to represent a network host
    #[derive(Default, PartialEq, Eq, Hash, Clone, Debug)]
    pub struct Host {
        /// Hostname (domain). Obtained from the reverse DNS.
        pub domain: String,
        /// Autonomous System which operates the host
        pub asn: Asn,
        /// Country
        pub country: Country,
    }
}

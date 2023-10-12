//! Module defining the `DataInfoHost` struct related to hosts.
pub mod data_info_host {
    use crate::types::{data_info::data_info::DataInfo, traffic_type::traffic_type::TrafficType};


    /// Host-related information.
    #[derive(Clone, Default)]
    pub struct DataInfoHost {
        /// Incoming and outgoing packets and bytes
        pub data_info: DataInfo,
        /// Determine if this host is one of the favorites
        pub is_favorite: bool,
        /// Determine if the connection with this host is local
        pub is_local: bool,
        /// Determine if the connection with this host is unicast, multicast, or broadcast
        pub traffic_type: TrafficType,
    }
}

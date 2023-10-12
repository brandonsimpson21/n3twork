pub mod address {
    use std::net::IpAddr;
    #[derive(Debug, Clone)]
    /// Address information for an interface
    pub struct Address {
        /// The address
        pub addr: IpAddr,
        /// Network mask for this address
        pub netmask: Option<IpAddr>,
        /// Broadcast address for this address
        pub broadcast_addr: Option<IpAddr>,
        /// P2P destination address for this address
        pub dst_addr: Option<IpAddr>,
    }

    impl Default for Address {
        fn default() -> Self {
            Self {
                addr: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                netmask: None,
                broadcast_addr: None,
                dst_addr: None,
            }
        }
    }

    impl Address {
        unsafe fn new(
            addr: IpAddr,
            netmask: Option<IpAddr>,
            broadcast_addr: Option<IpAddr>,
            dst_addr: Option<IpAddr>,
        ) -> Option<Address> {
            Some(Self {
                addr,
                netmask,
                broadcast_addr,
                dst_addr,
            })
        }

        #[cfg(not(target_os = "windows"))]
        unsafe fn convert_sockaddr(ptr: *const libc::sockaddr) -> Option<IpAddr> {
            if ptr.is_null() {
                return None;
            }

            match (*ptr).sa_family as i32 {
                libc::AF_INET => {
                    let ptr: *const libc::sockaddr_in = std::mem::transmute(ptr);
                    Some(IpAddr::V4(u32::from_be((*ptr).sin_addr.s_addr).into()))
                }

                libc::AF_INET6 => {
                    let ptr: *const libc::sockaddr_in6 = std::mem::transmute(ptr);
                    Some(IpAddr::V6((*ptr).sin6_addr.s6_addr.into()))
                }

                _ => None,
            }
        }

        #[cfg(target_os = "windows")]
        unsafe fn convert_sockaddr(ptr: *const libc::sockaddr) -> Option<IpAddr> {
            if ptr.is_null() {
                return None;
            }

            match (*ptr).sa_family as u32 {
                AF_INET => {
                    let ptr: *const SOCKADDR_IN = std::mem::transmute(ptr);
                    let addr: [u8; 4] = ((*ptr).sin_addr.S_un.S_addr).to_ne_bytes();
                    Some(IpAddr::from(addr))
                }
                AF_INET6 => {
                    let ptr: *const SOCKADDR_IN6 = std::mem::transmute(ptr);
                    let addr = (*ptr).sin6_addr.u.Byte;
                    Some(IpAddr::from(addr))
                }

                _ => None,
            }
        }
    }
}

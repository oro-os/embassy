//! DNS client compatible with the `embedded-nal-async` traits.
//!
//! This exists only for compatibility with crates that use `embedded-nal-async`.
//! Prefer using [`Stack::dns_query`](crate::Stack::dns_query) directly if you're
//! not using `embedded-nal-async`.

use core::fmt;

use heapless::Vec;
pub use smoltcp::socket::dns::{DnsQuery, QueryHandle, Socket};
pub(crate) use smoltcp::socket::dns::{GetQueryResultError, StartQueryError};
pub use smoltcp::wire::{DnsQueryType, DnsSrvRecord, IpAddress};

use crate::Stack;

const MAX_NAME_SIZE: usize = 255;

/// An owned DNS name in canonical, uncompressed wire format.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Name(Vec<u8, MAX_NAME_SIZE>);

impl Name {
    /// Returns the canonical, uncompressed wire-format bytes for this name.
    pub fn as_raw(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns this name as a borrowed smoltcp DNS name.
    pub fn as_smoltcp(&self) -> smoltcp::wire::DnsName<'_> {
        smoltcp::wire::DnsName::from_const(self.as_raw()).expect("stored embassy-net DNS names should stay canonical")
    }
}

impl TryFrom<&str> for Name {
    type Error = Error;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        let mut raw_name = [0u8; MAX_NAME_SIZE];
        let name = smoltcp::wire::DnsName::from_str(&mut raw_name, name).map_err(|_| Error::InvalidName)?;
        Ok(name.into())
    }
}

impl From<&Name> for Name {
    fn from(name: &Name) -> Self {
        name.clone()
    }
}

impl AsRef<[u8]> for Name {
    fn as_ref(&self) -> &[u8] {
        self.as_raw()
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_smoltcp().fmt(f)
    }
}

impl From<smoltcp::wire::DnsName<'_>> for Name {
    fn from(name: smoltcp::wire::DnsName<'_>) -> Self {
        let mut raw_name = [0u8; MAX_NAME_SIZE];
        let len = name
            .write_uncompressed(&mut raw_name)
            .expect("smoltcp DNS names should stay canonical");

        Vec::from_slice(&raw_name[..len])
            .map(Self)
            .expect("DNS names must fit within 255 bytes")
    }
}

impl From<smoltcp::socket::dns::QueryResult<'_>> for QueryResult {
    fn from(result: smoltcp::socket::dns::QueryResult<'_>) -> Self {
        match result {
            smoltcp::socket::dns::QueryResult::Address(addr) => Self::Address(addr),
            smoltcp::socket::dns::QueryResult::Ptr(name) => Self::Ptr(name.into()),
            smoltcp::socket::dns::QueryResult::Srv(srv) => Self::Srv(DnsSrvRecord {
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
                target: srv.target.into(),
            }),
        }
    }
}

/// An owned DNS SRV answer.
pub type SrvQueryResult = DnsSrvRecord<Name>;

/// A DNS answer.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum QueryResult {
    /// An address answer from an A or AAAA query.
    Address(IpAddress),
    /// A PTR answer.
    Ptr(Name),
    /// An SRV answer.
    Srv(SrvQueryResult),
}

/// Errors returned by DnsSocket.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    /// Invalid name
    InvalidName,
    /// Name too long
    NameTooLong,
    /// Name lookup failed
    Failed,
}

impl From<core::convert::Infallible> for Error {
    fn from(error: core::convert::Infallible) -> Self {
        match error {}
    }
}

impl From<GetQueryResultError> for Error {
    fn from(_: GetQueryResultError) -> Self {
        Self::Failed
    }
}

impl From<StartQueryError> for Error {
    fn from(e: StartQueryError) -> Self {
        match e {
            StartQueryError::NoFreeSlot => Self::Failed,
            StartQueryError::InvalidName => Self::InvalidName,
            StartQueryError::NameTooLong => Self::NameTooLong,
        }
    }
}

/// An iterator over the answers for a completed DNS query.
pub struct QueryResultIter<'a>(QueryResultIterInner<'a>);

enum QueryResultIterInner<'a> {
    Query {
        stack: Stack<'a>,
        query: QueryHandle,
        next_index: usize,
        needs_cancel: bool,
    },
    Done,
}

impl<'a> QueryResultIter<'a> {
    pub(crate) fn new(stack: Stack<'a>, query: QueryHandle) -> Self {
        Self(QueryResultIterInner::Query {
            stack,
            query,
            next_index: 0,
            needs_cancel: true,
        })
    }
}

impl Iterator for QueryResultIter<'_> {
    type Item = QueryResult;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            QueryResultIterInner::Done => None,
            QueryResultIterInner::Query {
                stack,
                query,
                next_index,
                needs_cancel,
            } => {
                let mut next_result = None;
                let mut release_query = false;

                stack.with_mut(|i| {
                    let socket = i.sockets.get_mut::<Socket>(i.dns_socket);
                    let mut results = match socket.get_query_result(*query) {
                        Ok(results) => results,
                        Err(_) => unreachable!("DNS query should stay completed while its iterator is alive"),
                    };

                    for _ in 0..*next_index {
                        if results.next().is_none() {
                            core::mem::forget(results);
                            socket.cancel_query(*query);
                            i.waker.wake();
                            i.dns_waker.wake();
                            release_query = true;
                            return;
                        }
                    }

                    next_result = results.next().map(Into::into);
                    if next_result.is_some() {
                        *next_index += 1;
                        core::mem::forget(results);
                    } else {
                        core::mem::forget(results);
                        socket.cancel_query(*query);
                        i.waker.wake();
                        i.dns_waker.wake();
                        release_query = true;
                    }
                });

                if release_query {
                    *needs_cancel = false;
                    self.0 = QueryResultIterInner::Done;
                }

                next_result
            }
        }
    }
}

impl Drop for QueryResultIter<'_> {
    fn drop(&mut self) {
        if let QueryResultIterInner::Query {
            stack,
            query,
            needs_cancel,
            ..
        } = &mut self.0
        {
            if !*needs_cancel {
                return;
            }

            stack.with_mut(|i| {
                let socket = i.sockets.get_mut::<Socket>(i.dns_socket);
                socket.cancel_query(*query);
                i.waker.wake();
                i.dns_waker.wake();
            });
            *needs_cancel = false;
        }
    }
}

/// DNS client compatible with the `embedded-nal-async` traits.
///
/// This exists only for compatibility with crates that use `embedded-nal-async`.
/// Prefer using [`Stack::dns_query`](crate::Stack::dns_query) directly if you're
/// not using `embedded-nal-async`.
pub struct DnsSocket<'a> {
    stack: Stack<'a>,
}

impl<'a> DnsSocket<'a> {
    /// Create a new DNS socket using the provided stack.
    ///
    /// NOTE: If using DHCP, make sure it has reconfigured the stack to ensure the DNS servers are updated.
    pub fn new(stack: Stack<'a>) -> Self {
        Self { stack }
    }

    /// Make a query for a given name and return the corresponding DNS answers.
    pub async fn query<N>(&self, name: N, qtype: DnsQueryType) -> Result<QueryResultIter<'a>, Error>
    where
        N: TryInto<Name>,
        Error: From<N::Error>,
    {
        self.stack.dns_query(name, qtype).await
    }
}

impl<'a> embedded_nal_async::Dns for DnsSocket<'a> {
    type Error = Error;

    async fn get_host_by_name(
        &self,
        host: &str,
        addr_type: embedded_nal_async::AddrType,
    ) -> Result<core::net::IpAddr, Self::Error> {
        use core::net::IpAddr;

        use embedded_nal_async::AddrType;

        let (qtype, secondary_qtype) = match addr_type {
            AddrType::IPv4 => (DnsQueryType::A, None),
            AddrType::IPv6 => (DnsQueryType::Aaaa, None),
            AddrType::Either => {
                #[cfg(not(feature = "proto-ipv6"))]
                let v6_first = false;
                #[cfg(feature = "proto-ipv6")]
                let v6_first = self.stack.config_v6().is_some();
                match v6_first {
                    true => (DnsQueryType::Aaaa, Some(DnsQueryType::A)),
                    false => (DnsQueryType::A, Some(DnsQueryType::Aaaa)),
                }
            }
        };

        #[cfg(feature = "proto-ipv4")]
        if matches!(qtype, DnsQueryType::A) {
            if let Ok(addr) = host.parse().map(IpAddress::Ipv4) {
                return Ok(match addr {
                    IpAddress::Ipv4(addr) => IpAddr::V4(addr),
                    #[cfg(feature = "proto-ipv6")]
                    IpAddress::Ipv6(_) => unreachable!(),
                });
            }
        }

        #[cfg(feature = "proto-ipv6")]
        if matches!(qtype, DnsQueryType::Aaaa) {
            if let Ok(addr) = host.parse().map(IpAddress::Ipv6) {
                return Ok(match addr {
                    #[cfg(feature = "proto-ipv4")]
                    IpAddress::Ipv4(_) => unreachable!(),
                    IpAddress::Ipv6(addr) => IpAddr::V6(addr),
                });
            }
        }

        let mut addrs = self
            .query(host, qtype)
            .await?
            .into_iter()
            .find_map(|result| match result {
                QueryResult::Address(addr) => Some(addr),
                QueryResult::Ptr(_) | QueryResult::Srv(_) => None,
            });
        if addrs.is_none() {
            if let Some(qtype) = secondary_qtype {
                addrs = self
                    .query(host, qtype)
                    .await?
                    .into_iter()
                    .find_map(|result| match result {
                        QueryResult::Address(addr) => Some(addr),
                        QueryResult::Ptr(_) | QueryResult::Srv(_) => None,
                    });
            }
        }
        if let Some(first) = addrs {
            Ok(match first {
                #[cfg(feature = "proto-ipv4")]
                IpAddress::Ipv4(addr) => IpAddr::V4(addr),
                #[cfg(feature = "proto-ipv6")]
                IpAddress::Ipv6(addr) => IpAddr::V6(addr),
            })
        } else {
            Err(Error::Failed)
        }
    }

    async fn get_host_by_address(&self, _addr: core::net::IpAddr, _result: &mut [u8]) -> Result<usize, Self::Error> {
        todo!()
    }
}

fn _assert_covariant<'a, 'b: 'a>(x: DnsSocket<'b>) -> DnsSocket<'a> {
    x
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidName => f.write_str("InvalidName"),
            Self::NameTooLong => f.write_str("NameTooLong"),
            Self::Failed => f.write_str("Failed"),
        }
    }
}
impl core::error::Error for Error {}

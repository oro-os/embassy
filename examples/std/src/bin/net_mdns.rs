use clap::Parser;
use embassy_executor::{Executor, Spawner};
use embassy_net::dns::{DnsQueryType, DnsSocket, Name, QueryResult};
use embassy_net::{Config, IpAddress, Ipv4Address, Ipv4Cidr, StackResources};
use embassy_net_tuntap::TunTapDevice;
use heapless::Vec;
use log::*;
use rand_core::{OsRng, TryRngCore};
use static_cell::StaticCell;

const MDNS_IPV4_MULTICAST: IpAddress = IpAddress::Ipv4(Ipv4Address::new(224, 0, 0, 251));

#[derive(Parser)]
#[clap(version = "1.0")]
struct Opts {
    /// TAP device name
    #[clap(long, default_value = "tap0")]
    tap: String,
    /// use a static IP instead of DHCP
    #[clap(long)]
    static_ip: bool,
    /// DNS-SD service type to query
    #[clap(long, default_value = "_http._tcp.local")]
    service: String,
}

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, TunTapDevice>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn main_task(spawner: Spawner) {
    let opts: Opts = Opts::parse();

    // Init network device
    let device = TunTapDevice::new(&opts.tap).unwrap();

    // Choose between dhcp or static ip
    let config = if opts.static_ip {
        Config::ipv4_static(embassy_net::StaticConfigV4 {
            address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 69, 1), 24),
            dns_servers: Vec::new(),
            gateway: Some(Ipv4Address::new(192, 168, 69, 100)),
        })
    } else {
        Config::dhcpv4(Default::default())
    };

    // Generate random seed
    let mut seed = [0; 8];
    OsRng.try_fill_bytes(&mut seed).unwrap();
    let seed = u64::from_le_bytes(seed);

    // Init network stack
    static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();
    let (stack, runner) = embassy_net::new(device, config, RESOURCES.init(StackResources::new()), seed);

    // Launch network task
    spawner.spawn(net_task(runner).unwrap());

    info!("waiting for network...");
    stack.wait_config_up().await;
    info!("network is up");

    stack.join_multicast_group(MDNS_IPV4_MULTICAST).unwrap();

    let dns = DnsSocket::new(stack);
    let mut names = Vec::<Name, 8>::new();

    info!("querying PTR records for {}...", opts.service);
    match dns.query(opts.service.as_str(), DnsQueryType::Ptr).await {
        Ok(results) => {
            for result in results {
                match result {
                    QueryResult::Ptr(name) => {
                        info!("PTR {}", name);
                        if names.push(name).is_err() {
                            warn!("too many PTR records, truncating results");
                            break;
                        }
                    }
                    other => debug!("ignoring non-PTR answer: {:?}", other),
                }
            }
        }
        Err(e) => {
            warn!("PTR query error: {:?}", e);
            return;
        }
    }

    if names.is_empty() {
        warn!("no PTR records found for {}", opts.service);
        return;
    }

    for name in names.iter() {
        info!("querying SRV records for {}...", name);
        match dns.query(name, DnsQueryType::Srv).await {
            Ok(results) => {
                let mut found = false;
                for result in results {
                    match result {
                        QueryResult::Srv(srv) => {
                            found = true;
                            info!(
                                "SRV {} priority={} weight={} port={} target={}",
                                name, srv.priority, srv.weight, srv.port, srv.target
                            );
                        }
                        other => debug!("ignoring non-SRV answer: {:?}", other),
                    }
                }

                if !found {
                    warn!("no SRV records found for {}", name);
                }
            }
            Err(e) => warn!("SRV query error for {}: {:?}", name, e),
        }
    }
}

static EXECUTOR: StaticCell<Executor> = StaticCell::new();

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .filter_module("async_io", log::LevelFilter::Info)
        .format_timestamp_nanos()
        .init();

    let executor = EXECUTOR.init(Executor::new());
    executor.run(|spawner| {
        spawner.spawn(main_task(spawner).unwrap());
    });
}

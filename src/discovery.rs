//! Discovery services
use crate::PeerId;
use anyhow::Result;
use futures::FutureExt;
use iroh_net::AddrInfo;
use pkarr::{
    dns::rdata::{RData, A, TXT},
    dns::{Name, Packet, ResourceRecord, CLASS},
    url::Url,
    Keypair, PkarrClient, SignedPacket,
};
use simple_mdns::{async_discovery::ServiceDiscovery, InstanceInformation, NetworkScope};
use std::{collections::BTreeSet, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;

const DERP_REGION_KEY: &str = "_derp_region.iroh.";

fn filter_txt(rr: &ResourceRecord) -> Option<String> {
    if rr.class != CLASS::IN {
        return None;
    }
    if let RData::TXT(txt) = &rr.rdata {
        String::try_from(txt.clone()).ok()
    } else {
        None
    }
}

fn filter_u16(rr: &ResourceRecord) -> Option<u16> {
    if rr.class != CLASS::IN {
        return None;
    }
    if let RData::A(A { address }) = rr.rdata {
        Some(address as _)
    } else {
        None
    }
}

fn packet_to_peer_addr(packet: &SignedPacket) -> AddrInfo {
    let direct_addresses = packet
        .resource_records("@")
        .filter_map(filter_txt)
        .filter_map(|addr| addr.parse().ok())
        .collect::<BTreeSet<SocketAddr>>();
    let derp_region = packet
        .resource_records(DERP_REGION_KEY)
        .find_map(filter_u16);
    AddrInfo {
        derp_region,
        direct_addresses,
    }
}

fn peer_addr_to_packet(keypair: &Keypair, info: &AddrInfo, ttl: u32) -> Result<SignedPacket> {
    let mut packet = Packet::new_reply(0);
    for addr in &info.direct_addresses {
        let addr = addr.to_string();
        packet.answers.push(ResourceRecord::new(
            Name::new("@").unwrap(),
            CLASS::IN,
            ttl,
            RData::TXT(TXT::try_from(addr.as_str())?.into_owned()),
        ));
    }
    if let Some(derp_region) = info.derp_region {
        packet.answers.push(ResourceRecord::new(
            Name::new(DERP_REGION_KEY).unwrap(),
            CLASS::IN,
            ttl,
            RData::A(A {
                address: derp_region as _,
            }),
        ));
    }
    Ok(SignedPacket::from_packet(keypair, &packet)?)
}

fn peer_addr_to_instance_info(addr: &AddrInfo) -> InstanceInformation {
    let mut instance_info = InstanceInformation::new();
    for addr in &addr.direct_addresses {
        instance_info.ip_addresses.push(addr.ip());
        instance_info.ports.push(addr.port());
    }
    instance_info
}

fn instance_info_to_peer_addr(instance_info: &InstanceInformation) -> AddrInfo {
    AddrInfo {
        derp_region: None,
        direct_addresses: instance_info.get_socket_addresses().collect(),
    }
}

struct InnerDiscovery {
    keypair: pkarr::Keypair,
    relay: Option<Url>,
    pkarr: Option<PkarrClient>,
    mdns: Option<RwLock<ServiceDiscovery>>,
    ttl: u32,
}

impl InnerDiscovery {
    pub fn new(
        secret: [u8; 32],
        relay: Option<Url>,
        dht: bool,
        mdns: bool,
        ttl: u32,
    ) -> Result<Self> {
        let keypair = Keypair::from_secret_key(&secret);
        let origin = keypair.public_key().to_z32();
        let mdns = if mdns {
            Some(RwLock::new(ServiceDiscovery::new_with_scope(
                &origin,
                "_pkarr.local",
                ttl,
                None,
                NetworkScope::V4,
            )?))
        } else {
            None
        };
        let pkarr = if dht || relay.is_some() {
            Some(PkarrClient::new())
        } else {
            None
        };
        Ok(Self {
            keypair,
            relay,
            pkarr,
            mdns,
            ttl,
        })
    }

    async fn resolve(&self, peer_id: &PeerId) -> Result<AddrInfo> {
        tracing::info!("resolving {}", peer_id);
        let origin = pkarr::PublicKey::try_from(*peer_id.as_bytes()).unwrap();
        let origin_z32 = origin.to_z32();
        if let Some(mdns) = self.mdns.as_ref() {
            if let Some(addr) = mdns
                .read()
                .await
                .get_known_services()
                .await
                .into_iter()
                .find(|(peer, _)| peer == &origin_z32)
                .map(|(_, instance_info)| instance_info_to_peer_addr(&instance_info))
            {
                tracing::info!("resolved: {} to {:?} via mdns", peer_id, addr);
                return Ok(addr);
            }
        }
        if let Some(pkarr) = self.pkarr.as_ref() {
            let msg = if let Some(relay) = self.relay.as_ref() {
                Some(pkarr.relay_get(relay, origin).await?)
            } else {
                pkarr.resolve(origin).await
            };
            if let Some(msg) = msg {
                let addr = packet_to_peer_addr(&msg);
                tracing::info!("resolved: {} to {:?}", peer_id, addr);
                return Ok(addr);
            }
        }
        anyhow::bail!("peer not found");
    }

    async fn publish(&self, addr: &AddrInfo) -> Result<()> {
        let instance_info = peer_addr_to_instance_info(addr);
        let packet = peer_addr_to_packet(&self.keypair, addr, self.ttl)?;
        if let Some(mdns) = self.mdns.as_ref() {
            mdns.write().await.add_service_info(instance_info).await?;
        }
        if let Some(pkarr) = self.pkarr.as_ref() {
            if let Some(relay) = self.relay.as_ref() {
                tracing::info!("publishing {:?} via relay {}", addr, relay);
                pkarr.relay_put(relay, packet).await?;
            } else {
                tracing::info!("publishing {:?} via dht", addr);
                pkarr.publish(&packet).await?;
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Discovery(Arc<InnerDiscovery>);

impl std::fmt::Debug for Discovery {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Discovery")
    }
}

impl Discovery {
    pub fn new(
        secret: [u8; 32],
        relay: Option<Url>,
        dht: bool,
        mdns: bool,
        ttl: u32,
    ) -> Result<Self> {
        Ok(Self(Arc::new(InnerDiscovery::new(
            secret, relay, dht, mdns, ttl,
        )?)))
    }

    pub async fn resolve(&self, peer_id: &PeerId) -> Result<AddrInfo> {
        self.0.resolve(peer_id).await
    }

    pub async fn publish(&self, addr: &AddrInfo) -> Result<()> {
        self.0.publish(addr).await
    }
}

impl iroh_net::magicsock::Discovery for Discovery {
    fn publish(&self, addr: &AddrInfo) {
        let discovery = self.clone();
        let addr = addr.clone();
        tokio::spawn(async move {
            match discovery.publish(&addr).await {
                Ok(()) => tracing::info!("done publishing"),
                Err(err) => tracing::info!("failed to publish: {}", err),
            }
        });
    }

    fn resolve<'a>(
        &'a self,
        node_id: &'a PeerId,
    ) -> futures::future::BoxFuture<'a, Result<AddrInfo>> {
        self.resolve(node_id).boxed()
    }
}

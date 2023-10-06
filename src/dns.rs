use crate::PeerId;
use anyhow::Result;
use iroh_net::{AddrInfo, PeerAddr};
use pkarr::dns::rdata::{RData, A, AAAA, TXT};
use pkarr::dns::{Name, Packet, ResourceRecord, CLASS};
use pkarr::{Keypair, SignedPacket};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

const DERP_REGION_KEY: &str = "_derp_region.iroh.";

#[allow(unused)]
fn filter_ipaddr(rr: &ResourceRecord) -> Option<IpAddr> {
    if rr.class != CLASS::IN {
        return None;
    }
    let addr: IpAddr = match rr.rdata {
        RData::A(A { address }) => IpAddr::V4(address.into()),
        RData::AAAA(AAAA { address }) => IpAddr::V6(address.into()),
        _ => return None,
    };
    Some(addr)
}

fn filter_txt<'a>(rr: &'a ResourceRecord) -> Option<String> {
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

pub fn packet_to_peer_addr(peer_id: &PeerId, packet: &SignedPacket) -> PeerAddr {
    let direct_addresses = packet
        .resource_records("@")
        .filter_map(filter_txt)
        .filter_map(|addr| addr.parse().ok())
        .collect::<HashSet<SocketAddr>>();
    let derp_region = packet
        .resource_records(DERP_REGION_KEY)
        .find_map(filter_u16);
    PeerAddr {
        peer_id: *peer_id,
        info: AddrInfo {
            derp_region,
            direct_addresses,
        },
    }
}

pub fn peer_addr_to_packet(secret: &[u8; 32], addr: &PeerAddr) -> Result<SignedPacket> {
    let mut packet = Packet::new_reply(0);
    for addr in &addr.info.direct_addresses {
        let addr = addr.to_string();
        packet.answers.push(ResourceRecord::new(
            Name::new("@").unwrap(),
            CLASS::IN,
            30,
            RData::TXT(TXT::try_from(addr.as_str())?.into_owned()),
        ));
    }
    if let Some(derp_region) = addr.info.derp_region {
        packet.answers.push(ResourceRecord::new(
            Name::new(DERP_REGION_KEY).unwrap(),
            CLASS::IN,
            30,
            RData::A(A {
                address: derp_region as _,
            }),
        ));
    }

    let keypair = Keypair::from_secret_key(&secret);
    Ok(SignedPacket::from_packet(&keypair, &packet)?)
}

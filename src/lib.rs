use anyhow::Result;
use iroh_net::derp::DerpMap;
use iroh_net::key::SecretKey;
use iroh_net::magic_endpoint::accept_conn;
use iroh_net::{AddrInfo, MagicEndpoint, PeerAddr};
use pkarr::dns::rdata::{RData, A, AAAA, TXT};
use pkarr::dns::{Name, Packet, ResourceRecord, CLASS};
use pkarr::{Bep44Args, RelayClient};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub use quinn::{Connection, RecvStream, SendStream};

pub type PeerId = iroh_net::key::PublicKey;

const DERP_REGION_KEY: &str = "_derp_region.iroh.";

#[allow(unused)]
fn filter_ipaddr(rr: &ResourceRecord, name: &str) -> Option<IpAddr> {
    if rr.name != Name::new(name).unwrap() || rr.class != CLASS::IN {
        return None;
    }
    let addr: IpAddr = match rr.rdata {
        RData::A(A { address }) => IpAddr::V4(address.into()),
        RData::AAAA(AAAA { address }) => IpAddr::V6(address.into()),
        _ => return None,
    };
    Some(addr)
}

fn filter_txt<'a>(rr: &'a ResourceRecord, name: &str) -> Option<String> {
    if rr.name != Name::new(name).unwrap() || rr.class != CLASS::IN {
        return None;
    }
    if let RData::TXT(txt) = &rr.rdata {
        String::try_from(txt.clone()).ok()
    } else {
        None
    }
}

fn filter_u16(rr: &ResourceRecord, name: &str) -> Option<u16> {
    if rr.name != Name::new(name).unwrap() || rr.class != CLASS::IN {
        return None;
    }
    if let RData::A(A { address }) = rr.rdata {
        Some(address as _)
    } else {
        None
    }
}

pub struct Endpoint {
    secret: [u8; 32],
    alpn: Vec<u8>,
    endpoint: MagicEndpoint,
    pkarr: RelayClient,
}

impl Endpoint {
    pub async fn new(
        secret: [u8; 32],
        alpn: &[u8],
        port: u16,
        pkarr_relay: &str,
        derp_map: Option<DerpMap>,
    ) -> Result<Self> {
        let pkarr = RelayClient::new(pkarr_relay)?;
        let builder = MagicEndpoint::builder()
            .secret_key(SecretKey::from(secret))
            .alpns(vec![alpn.to_vec()]);
        let builder = if let Some(derp_map) = derp_map {
            builder.enable_derp(derp_map)
        } else {
            builder
        };
        let endpoint = builder.bind(port).await?;
        Ok(Self {
            secret,
            alpn: alpn.to_vec(),
            endpoint,
            pkarr,
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.endpoint.peer_id()
    }

    pub async fn resolve(&self, peer_id: &PeerId) -> Result<PeerAddr> {
        let msg = self
            .pkarr
            .get(pkarr::PublicKey::try_from(*peer_id.as_bytes()).unwrap())
            .await?;
        let packet = msg.packet()?;
        let direct_addresses = packet
            .answers
            .iter()
            .filter_map(|rr| filter_txt(rr, "@"))
            .filter_map(|addr| addr.parse().ok())
            .collect::<HashSet<SocketAddr>>();
        let derp_region = packet
            .answers
            .iter()
            .find_map(|rr| filter_u16(rr, DERP_REGION_KEY));
        Ok(PeerAddr {
            peer_id: *peer_id,
            info: AddrInfo {
                derp_region,
                direct_addresses,
            },
        })
    }

    pub async fn publish(&self) -> Result<()> {
        let addr = self.endpoint.my_addr().await?;
        let mut packet = Packet::new_reply(0);
        for addr in addr.info.direct_addresses {
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
        let keypair = pkarr::Keypair::from_secret_key(&self.secret);
        let packet = Bep44Args::from_packet(&keypair, &packet)?;
        self.pkarr.put(packet).await?;
        Ok(())
    }

    pub async fn connect(&self, addr: PeerAddr) -> Result<Connection> {
        Ok(self.endpoint.connect(addr, &self.alpn).await?)
    }

    pub async fn accept(&self) -> Result<Connection> {
        let Some(conn) = self.endpoint.accept().await else {
            anyhow::bail!("socket closed");
        };
        let (_peer_id, alpn, conn) = accept_conn(conn).await?;
        if self.alpn != alpn.as_bytes() {
            anyhow::bail!("unexpected alpn {}", alpn);
        }
        Ok(conn)
    }
}

pub async fn send_one<T: Serialize>(tx: &mut SendStream, msg: &T) -> Result<()> {
    let bytes = bincode::serialize(msg)?;
    let len: u16 = bytes.len().try_into()?;
    tx.write_u16(len).await?;
    tx.write_all(&bytes).await?;
    Ok(())
}

pub async fn recv_one<T: DeserializeOwned>(rx: &mut RecvStream, buf: &mut Vec<u8>) -> Result<T> {
    let len = rx.read_u16().await?;
    buf.clear();
    rx.take(len as _).read_to_end(buf).await?;
    Ok(bincode::deserialize(&buf)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_net::defaults::TEST_REGION_ID;
    use serde::{Deserialize, Serialize};
    use std::time::Duration;

    const ALPN: &[u8] = b"/analog/tss/1";
    const PKARR_RELAY: &str = "http://127.0.0.1:6881";
    const PORT: u16 = 33000;

    #[derive(Deserialize, Serialize)]
    struct Ping(u16);

    #[derive(Deserialize, Serialize)]
    struct Pong(u16);

    async fn ping(conn: &mut Connection) -> Result<Pong> {
        let (mut tx, mut rx) = conn.open_bi().await?;
        let mut buf = Vec::with_capacity(1024);
        send_one(&mut tx, &Ping(42)).await?;
        tx.finish().await?;
        Ok(recv_one(&mut rx, &mut buf).await?)
    }

    async fn pong(conn: &mut Connection) -> Result<()> {
        let (mut tx, mut rx) = conn.accept_bi().await?;
        let mut buf = Vec::with_capacity(1024);
        let ping: Ping = recv_one(&mut rx, &mut buf).await?;
        send_one(&mut tx, &Pong(ping.0)).await?;
        tx.finish().await?;
        Ok(())
    }

    #[tokio::test]
    async fn smoke() -> Result<()> {
        env_logger::try_init().ok();
        log::info!("starting test");
        let derp_map = DerpMap::from_url("http://127.0.0.1:3340".parse().unwrap(), TEST_REGION_ID);
        let e1 = Endpoint::new([1; 32], ALPN, PORT, PKARR_RELAY, Some(derp_map.clone())).await?;
        let e2 =
            Endpoint::new([2; 32], ALPN, PORT + 1, PKARR_RELAY, Some(derp_map.clone())).await?;
        let p1 = e1.peer_id();
        log::info!("created endpoints");
        tokio::time::sleep(Duration::from_secs(5)).await;
        e1.publish().await.unwrap();
        log::info!("published record");
        tokio::spawn(async move {
            loop {
                if let Ok(mut conn) = e1.accept().await {
                    log::info!("accepted connection");
                    tokio::spawn(async move { dbg!(pong(&mut conn).await) });
                }
            }
        });
        let addr = e2.resolve(&p1).await?;
        log::info!("resolved record {:?}", addr);
        let mut conn = e2.connect(addr).await?;
        log::info!("connected");
        let pong = ping(&mut conn).await?;
        log::info!("response");
        assert_eq!(pong.0, 42);
        Ok(())
    }
}

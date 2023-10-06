use anyhow::Result;
use iroh_net::defaults::{default_derp_map, TEST_REGION_ID};
use iroh_net::derp::{DerpMap, DerpMode};
use iroh_net::key::SecretKey;
use iroh_net::magic_endpoint::accept_conn;
use iroh_net::{MagicEndpoint, PeerAddr};
use pkarr::url::Url;
use pkarr::{PkarrClient, DEFAULT_PKARR_RELAY};

mod dns;
mod protocol;

pub use crate::protocol::{
    NotificationHandler, Protocol, ProtocolHandler, ProtocolHandlerBuilder, RequestHandler,
    Subscription, SubscriptionHandler,
};
pub use quinn::{Connection, RecvStream, SendStream};
pub type PeerId = iroh_net::key::PublicKey;

pub struct EndpointBuilder {
    alpn: Vec<u8>,
    handler: ProtocolHandler,
    secret: Option<[u8; 32]>,
    port: u16,
    pkarr_relay: Option<Url>,
    derp_map: Option<DerpMap>,
}

impl EndpointBuilder {
    pub fn new(alpn: Vec<u8>, handler: ProtocolHandler) -> Self {
        Self {
            alpn,
            handler,
            secret: None,
            port: 0,
            pkarr_relay: None,
            derp_map: None,
        }
    }

    pub fn secret(&mut self, secret: [u8; 32]) -> &mut Self {
        self.secret = Some(secret);
        self
    }

    pub fn port(&mut self, port: u16) -> &mut Self {
        self.port = port;
        self
    }

    pub fn relay(&mut self, relay: Url) -> &mut Self {
        self.pkarr_relay = Some(relay);
        self
    }

    pub fn localhost_relay(&mut self) -> &mut Self {
        self.pkarr_relay = Some("http://127.0.0.1:6881".parse().unwrap());
        self
    }

    pub fn pkarr_relay(&mut self) -> &mut Self {
        self.pkarr_relay = Some(DEFAULT_PKARR_RELAY.parse().unwrap());
        self
    }

    pub fn derp_map(&mut self, map: DerpMap) -> &mut Self {
        self.derp_map = Some(map);
        self
    }

    pub fn localhost_derp_map(&mut self) -> &mut Self {
        self.derp_map = Some(DerpMap::from_url(
            "http://127.0.0.1:3340".parse().unwrap(),
            TEST_REGION_ID,
        ));
        self
    }

    pub fn iroh_derp_map(&mut self) -> &mut Self {
        self.derp_map = Some(default_derp_map());
        self
    }

    pub async fn build(self) -> Result<Endpoint> {
        let secret = self.secret.unwrap_or_else(|| {
            let mut secret = [0; 32];
            getrandom::getrandom(&mut secret).unwrap();
            secret
        });
        let relay = self
            .pkarr_relay
            .unwrap_or_else(|| "http://127.0.0.1:6881".parse().unwrap());
        Endpoint::new(
            secret,
            self.alpn,
            self.port,
            relay,
            self.derp_map,
            self.handler,
        )
        .await
    }
}

#[derive(Clone)]
pub struct Endpoint {
    secret: [u8; 32],
    alpn: Vec<u8>,
    endpoint: MagicEndpoint,
    pkarr: PkarrClient,
    pkarr_relay: Url,
}

impl Endpoint {
    pub fn builder(alpn: Vec<u8>, handler: ProtocolHandler) -> EndpointBuilder {
        EndpointBuilder::new(alpn, handler)
    }

    async fn new(
        secret: [u8; 32],
        alpn: Vec<u8>,
        port: u16,
        pkarr_relay: Url,
        derp_map: Option<DerpMap>,
        handler: ProtocolHandler,
    ) -> Result<Self> {
        let pkarr = PkarrClient::new();
        let builder = MagicEndpoint::builder()
            .secret_key(SecretKey::from(secret))
            .alpns(vec![alpn.clone()]);
        let builder = if let Some(derp_map) = derp_map {
            builder.derp_mode(DerpMode::Custom(derp_map))
        } else {
            builder.derp_mode(DerpMode::Disabled)
        };
        let endpoint = builder.bind(port).await?;
        tokio::spawn(server(endpoint.clone(), handler));
        Ok(Self {
            secret,
            alpn,
            endpoint,
            pkarr_relay,
            pkarr,
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.endpoint.peer_id()
    }

    pub async fn addr(&self) -> Result<PeerAddr> {
        Ok(self.endpoint.my_addr().await?)
    }

    // TODO: cache peer addresses
    // TODO: support mdns
    async fn resolve(&self, peer_id: &PeerId) -> Result<PeerAddr> {
        let msg = self
            .pkarr
            .relay_get(
                &self.pkarr_relay,
                pkarr::PublicKey::try_from(*peer_id.as_bytes()).unwrap(),
            )
            .await?;
        Ok(crate::dns::packet_to_peer_addr(peer_id, &msg))
    }

    // TODO: once the socket support notifying address changes we can handle publishing
    // automatically and make this private
    // TODO: support mdns
    pub async fn publish(&self) -> Result<()> {
        let addr = self.addr().await?;
        let packet = crate::dns::peer_addr_to_packet(&self.secret, &addr)?;
        self.pkarr.relay_put(&self.pkarr_relay, packet).await?;
        Ok(())
    }

    pub async fn connect(&self, peer_id: &PeerId) -> Result<Connection> {
        let addr = self.resolve(peer_id).await?;
        Ok(self.endpoint.connect(addr, &self.alpn).await?)
    }

    pub async fn notify<P: Protocol>(&self, peer_id: &PeerId, msg: &P::Request) -> Result<()> {
        let mut conn = self.connect(peer_id).await?;
        crate::protocol::notify::<P>(&mut conn, msg).await
    }

    pub async fn request<P: Protocol>(
        &self,
        peer_id: &PeerId,
        msg: &P::Request,
    ) -> Result<P::Response> {
        let mut conn = self.connect(peer_id).await?;
        crate::protocol::request_response::<P>(&mut conn, msg).await
    }

    pub async fn subscribe<P: Protocol>(
        &self,
        peer_id: &PeerId,
        msg: &P::Request,
    ) -> Result<Subscription<P::Response>> {
        let mut conn = self.connect(peer_id).await?;
        crate::protocol::subscribe::<P>(&mut conn, msg).await
    }
}

async fn server(endpoint: MagicEndpoint, handler: ProtocolHandler) {
    loop {
        let Some(conn) = endpoint.accept().await else {
            log::info!("socket closed");
            break;
        };
        match accept_conn(conn).await {
            Ok((peer_id, _alpn, conn)) => {
                handler.handle(peer_id, conn);
            }
            Err(err) => {
                dbg!(err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::channel::oneshot;
    use serde::{Deserialize, Serialize};
    use std::time::Duration;

    const ALPN: &[u8] = b"/analog/tss/1";

    #[derive(Deserialize, Serialize)]
    pub struct Ping(u16);

    #[derive(Deserialize, Serialize)]
    pub struct Pong(u16);

    pub struct PingPong;

    impl Protocol for PingPong {
        const ID: u16 = 0;
        const REQ_BUF: usize = 1024;
        const RES_BUF: usize = 1024;
        type Request = Ping;
        type Response = Pong;
    }

    impl RequestHandler<Self> for PingPong {
        fn request(
            &self,
            _peer_id: PeerId,
            request: <Self as Protocol>::Request,
            response: oneshot::Sender<<Self as Protocol>::Response>,
        ) -> Result<()> {
            response
                .send(Pong(request.0))
                .map_err(|_| anyhow::anyhow!("response channel closed"))?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn request_response() -> Result<()> {
        env_logger::try_init().ok();

        let mut builder = ProtocolHandler::builder();
        builder.register_request_handler(PingPong);
        let handler = builder.build();

        let mut builder = Endpoint::builder(ALPN.to_vec(), handler.clone());
        builder.localhost_relay();
        builder.localhost_derp_map();
        let e1 = builder.build().await?;

        let mut builder = Endpoint::builder(ALPN.to_vec(), handler);
        builder.localhost_relay();
        builder.localhost_derp_map();
        let e2 = builder.build().await?;
        log::info!("created endpoints");

        let p1 = e1.peer_id();
        loop {
            let addr = e1.addr().await?;
            if addr.info.direct_addresses.is_empty() {
                log::info!("waiting for addr");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            log::info!("publishing {:?}", addr);
            e1.publish().await?;
            break;
        }
        log::info!("published record");

        loop {
            let addr = e2.resolve(&p1).await?;
            if addr.info.direct_addresses.is_empty() {
                log::info!("waiting for addr");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            log::info!("resolved {:?}", addr);
            let pong = e2.request::<PingPong>(&p1, &Ping(42)).await?;
            assert_eq!(pong.0, 42);
            break;
        }
        Ok(())
    }
}

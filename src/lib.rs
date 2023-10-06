use crate::discovery::Discovery;
use anyhow::Result;
use iroh_net::defaults::{default_derp_map, TEST_REGION_ID};
use iroh_net::derp::{DerpMap, DerpMode};
use iroh_net::key::SecretKey;
use iroh_net::magic_endpoint::accept_conn;
use iroh_net::{MagicEndpoint, PeerAddr};
use pkarr::url::Url;
use pkarr::DEFAULT_PKARR_RELAY;
use std::sync::Arc;
use tokio::sync::Mutex;

mod discovery;
mod protocol;

pub use crate::protocol::{
    NotificationHandler, Protocol, ProtocolHandler, ProtocolHandlerBuilder, RequestHandler,
    Subscription, SubscriptionHandler,
};
pub use quinn::{Connection, RecvStream, SendStream};
pub type PeerId = iroh_net::key::PublicKey;

pub struct EndpointBuilder {
    alpn: Vec<u8>,
    handler: Option<ProtocolHandler>,
    secret: Option<[u8; 32]>,
    port: u16,
    pkarr_relay: Option<Url>,
    derp_map: Option<DerpMap>,
    ttl: Option<u32>,
    enable_mdns: bool,
}

impl EndpointBuilder {
    pub fn new(alpn: Vec<u8>) -> Self {
        Self {
            alpn,
            handler: None,
            secret: None,
            port: 0,
            pkarr_relay: None,
            derp_map: None,
            ttl: None,
            enable_mdns: false,
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

    pub fn handler(&mut self, handler: ProtocolHandler) -> &mut Self {
        self.handler = Some(handler);
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

    pub fn enable_mdns(&mut self) -> &mut Self {
        self.enable_mdns = true;
        self
    }

    pub fn ttl(&mut self, ttl: u32) -> &mut Self {
        self.ttl = Some(ttl);
        self
    }

    pub async fn build(self) -> Result<Endpoint> {
        let secret = self.secret.unwrap_or_else(|| {
            let mut secret = [0; 32];
            getrandom::getrandom(&mut secret).unwrap();
            secret
        });
        let ttl = self.ttl.unwrap_or(30);
        Endpoint::new(
            secret,
            self.alpn,
            self.port,
            self.pkarr_relay,
            self.derp_map,
            self.handler,
            ttl,
            self.enable_mdns,
        )
        .await
    }
}

#[derive(Clone)]
pub struct Endpoint {
    alpn: Vec<u8>,
    endpoint: MagicEndpoint,
    discovery: Arc<Mutex<Discovery>>,
}

impl Endpoint {
    pub fn builder(alpn: Vec<u8>) -> EndpointBuilder {
        EndpointBuilder::new(alpn)
    }

    async fn new(
        secret: [u8; 32],
        alpn: Vec<u8>,
        port: u16,
        relay: Option<Url>,
        derp_map: Option<DerpMap>,
        handler: Option<ProtocolHandler>,
        ttl: u32,
        enable_mdns: bool,
    ) -> Result<Self> {
        let builder = MagicEndpoint::builder()
            .secret_key(SecretKey::from(secret))
            .alpns(vec![alpn.clone()]);
        let builder = if let Some(derp_map) = derp_map {
            builder.derp_mode(DerpMode::Custom(derp_map))
        } else {
            builder.derp_mode(DerpMode::Disabled)
        };
        let endpoint = builder.bind(port).await?;
        let discovery = Arc::new(Mutex::new(Discovery::new(secret, relay, enable_mdns, ttl)?));
        if let Some(handler) = handler {
            tokio::spawn(server(endpoint.clone(), handler));
        }
        Ok(Self {
            alpn,
            endpoint,
            discovery,
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.endpoint.peer_id()
    }

    pub async fn addr(&self) -> Result<PeerAddr> {
        Ok(self.endpoint.my_addr().await?)
    }

    pub async fn add_address(&self, address: PeerAddr) {
        self.discovery.lock().await.add_address(address);
    }

    async fn resolve(&self, peer_id: &PeerId) -> Result<PeerAddr> {
        self.discovery.lock().await.resolve(peer_id).await
    }

    // TODO: once the socket support notifying address changes we can handle publishing
    // automatically and make this private
    pub async fn publish(&self) -> Result<()> {
        let addr = self.addr().await?;
        self.discovery.lock().await.publish(&addr).await
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
    use futures::channel::{mpsc, oneshot};
    use futures::SinkExt;
    use serde::{Deserialize, Serialize};
    use std::sync::Mutex;
    use std::time::Duration;

    const ALPN: &[u8] = b"/analog/tss/1";

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Ping(u16);

    #[derive(Debug, Deserialize, Serialize)]
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

    impl SubscriptionHandler<Self> for PingPong {
        fn subscribe(
            &self,
            _peer_id: PeerId,
            request: <Self as Protocol>::Request,
            mut response: mpsc::Sender<<Self as Protocol>::Response>,
        ) -> Result<()> {
            tokio::spawn(async move {
                response.send(Pong(request.0)).await.unwrap();
                response.send(Pong(request.0)).await.unwrap();
            });
            Ok(())
        }
    }

    pub struct Pinger(Mutex<Option<oneshot::Sender<Ping>>>);

    impl Pinger {
        pub fn new() -> (Self, oneshot::Receiver<Ping>) {
            let (tx, rx) = oneshot::channel();
            (Self(Mutex::new(Some(tx))), rx)
        }
    }

    impl NotificationHandler<PingPong> for Pinger {
        fn notify(&self, _peer_id: PeerId, request: Ping) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(request)
                .unwrap();
            Ok(())
        }
    }

    async fn wait_for_publish(endpoint: &Endpoint) -> Result<PeerAddr> {
        loop {
            let addr = endpoint.addr().await?;
            if addr.info.direct_addresses.is_empty() {
                log::info!("waiting for publish");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            return Ok(addr);
        }
    }

    async fn wait_for_resolve(endpoint: &Endpoint, peer_id: &PeerId) -> Result<PeerAddr> {
        loop {
            let addr = endpoint.resolve(peer_id).await?;
            if addr.info.direct_addresses.is_empty() {
                log::info!("waiting for resolve");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            return Ok(addr);
        }
    }

    #[tokio::test]
    async fn mdns() -> Result<()> {
        env_logger::try_init().ok();

        let mut builder = Endpoint::builder(ALPN.to_vec());
        builder.enable_mdns();
        let e1 = builder.build().await?;
        let p1 = e1.peer_id();

        let mut builder = Endpoint::builder(ALPN.to_vec());
        builder.enable_mdns();
        let e2 = builder.build().await?;

        let a1 = wait_for_publish(&e1).await?;
        log::info!("publishing {:?}", a1);
        e1.publish().await?;
        log::info!("published record");

        let a1_2 = wait_for_resolve(&e2, &p1).await?;
        log::info!("resolved {:?}", a1_2);

        assert_eq!(a1, a1_2);
        Ok(())
    }

    #[tokio::test]
    async fn pkarr() -> Result<()> {
        env_logger::try_init().ok();

        let mut builder = Endpoint::builder(ALPN.to_vec());
        builder.localhost_relay();
        let e1 = builder.build().await?;
        let p1 = e1.peer_id();

        let mut builder = Endpoint::builder(ALPN.to_vec());
        builder.localhost_relay();
        let e2 = builder.build().await?;

        let a1 = wait_for_publish(&e1).await?;
        log::info!("publishing {:?}", a1);
        e1.publish().await?;
        log::info!("published record");

        let a1_2 = wait_for_resolve(&e2, &p1).await?;
        log::info!("resolved {:?}", a1_2);

        assert_eq!(a1, a1_2);
        Ok(())
    }

    #[tokio::test]
    async fn notify() -> Result<()> {
        env_logger::try_init().ok();

        let (pinger, rx) = Pinger::new();
        let mut builder = ProtocolHandler::builder();
        builder.register_notification_handler(pinger);
        let handler = builder.build();

        let mut builder = Endpoint::builder(ALPN.to_vec());
        builder.handler(handler);
        let e1 = builder.build().await?;
        let p1 = e1.peer_id();

        let builder = Endpoint::builder(ALPN.to_vec());
        let e2 = builder.build().await?;

        let a1 = wait_for_publish(&e1).await?;

        e2.add_address(a1).await;
        e2.notify::<PingPong>(&p1, &Ping(42)).await?;
        let ping = rx.await?;
        assert_eq!(ping.0, 42);
        Ok(())
    }

    #[tokio::test]
    async fn request_response() -> Result<()> {
        env_logger::try_init().ok();

        let mut builder = ProtocolHandler::builder();
        builder.register_request_handler(PingPong);
        let handler = builder.build();

        let mut builder = Endpoint::builder(ALPN.to_vec());
        builder.handler(handler);
        let e1 = builder.build().await?;
        let p1 = e1.peer_id();

        let builder = Endpoint::builder(ALPN.to_vec());
        let e2 = builder.build().await?;

        let a1 = wait_for_publish(&e1).await?;

        e2.add_address(a1).await;
        let pong = e2.request::<PingPong>(&p1, &Ping(42)).await?;
        assert_eq!(pong.0, 42);
        Ok(())
    }

    #[tokio::test]
    async fn subscribe() -> Result<()> {
        env_logger::try_init().ok();

        let mut builder = ProtocolHandler::builder();
        builder.register_subscription_handler(PingPong);
        let handler = builder.build();

        let mut builder = Endpoint::builder(ALPN.to_vec());
        builder.handler(handler);
        let e1 = builder.build().await?;
        let p1 = e1.peer_id();

        let builder = Endpoint::builder(ALPN.to_vec());
        let e2 = builder.build().await?;

        let a1 = wait_for_publish(&e1).await?;

        e2.add_address(a1).await;
        let mut subscription = e2.subscribe::<PingPong>(&p1, &Ping(42)).await?;
        while let Some(pong) = subscription.next().await? {
            assert_eq!(pong.0, 42);
        }
        Ok(())
    }
}

use anyhow::Result;
use futures::StreamExt;
use iroh_net::defaults::prod::default_relay_map;
use iroh_net::discovery::dns::{DnsDiscovery, N0_DNS_NODE_ORIGIN_PROD};
use iroh_net::discovery::pkarr::{
    PkarrPublisher, PkarrResolver, DEFAULT_REPUBLISH_INTERVAL, N0_DNS_PKARR_RELAY_PROD,
};
use iroh_net::discovery::{ConcurrentDiscovery, Discovery};
use iroh_net::endpoint::Endpoint as MagicEndpoint;
use iroh_net::key::SecretKey;
use iroh_net::relay::{RelayMap, RelayMode};
use iroh_net::{AddrInfo, NodeAddr};
use std::time::Duration;

mod protocol;

pub use crate::protocol::{
    NotificationHandler, Protocol, ProtocolHandler, ProtocolHandlerBuilder, RequestHandler,
    Subscription, SubscriptionHandler,
};
pub use iroh_net::endpoint::{Connection, RecvStream, SendStream};
pub type PeerId = iroh_net::key::PublicKey;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolverMode {
    Pkarr,
    Dns,
}

pub struct EndpointBuilder {
    alpn: Vec<u8>,
    handler: Option<ProtocolHandler>,
    secret: Option<[u8; 32]>,
    relay_map: Option<RelayMap>,
    // discovery fields
    resolver_mode: ResolverMode,
    dns_origin: String,
    pkarr_relay: String,
    publish_ttl: Duration,
    republish_interval: Duration,
}

impl EndpointBuilder {
    pub fn new(alpn: Vec<u8>) -> Self {
        Self {
            alpn,
            handler: None,
            secret: None,
            relay_map: Some(default_relay_map()),
            resolver_mode: ResolverMode::Pkarr,
            dns_origin: N0_DNS_NODE_ORIGIN_PROD.into(),
            pkarr_relay: N0_DNS_PKARR_RELAY_PROD.into(),
            publish_ttl: DEFAULT_REPUBLISH_INTERVAL * 4,
            republish_interval: DEFAULT_REPUBLISH_INTERVAL,
        }
    }

    pub fn secret(&mut self, secret: [u8; 32]) -> &mut Self {
        self.secret = Some(secret);
        self
    }

    pub fn handler(&mut self, handler: ProtocolHandler) -> &mut Self {
        self.handler = Some(handler);
        self
    }

    pub fn relay_map(&mut self, relay_map: Option<RelayMap>) -> &mut Self {
        self.relay_map = relay_map;
        self
    }

    pub fn resolver_mode(&mut self, mode: ResolverMode) -> &mut Self {
        self.resolver_mode = mode;
        self
    }

    pub fn dns_origin(&mut self, dns_origin: impl Into<String>) -> &mut Self {
        self.dns_origin = dns_origin.into();
        self
    }

    pub fn pkarr_relay(&mut self, pkarr_relay: impl Into<String>) -> &mut Self {
        self.pkarr_relay = pkarr_relay.into();
        self
    }

    pub fn republish_interval(&mut self, interval: Duration) -> &mut Self {
        self.republish_interval = interval;
        self
    }

    pub fn publish_ttl(&mut self, ttl: Duration) -> &mut Self {
        self.publish_ttl = ttl;
        self
    }

    pub async fn build(self) -> Result<Endpoint> {
        let secret = self.secret.unwrap_or_else(|| {
            let mut secret = [0; 32];
            getrandom::getrandom(&mut secret).unwrap();
            secret
        });
        Endpoint::new(
            SecretKey::from(secret),
            self.alpn,
            self.relay_map,
            self.handler,
            self.resolver_mode,
            self.pkarr_relay,
            self.dns_origin,
            self.publish_ttl,
            self.republish_interval,
        )
        .await
    }
}

#[derive(Clone)]
pub struct Endpoint {
    alpn: Vec<u8>,
    endpoint: MagicEndpoint,
}

impl Endpoint {
    pub fn builder(alpn: Vec<u8>) -> EndpointBuilder {
        EndpointBuilder::new(alpn)
    }

    async fn new(
        secret: SecretKey,
        alpn: Vec<u8>,
        relay_map: Option<RelayMap>,
        handler: Option<ProtocolHandler>,
        resolver_mode: ResolverMode,
        pkarr_relay: String,
        dns_origin: String,
        ttl: Duration,
        republish_interval: Duration,
    ) -> Result<Self> {
        let publisher = Box::new(PkarrPublisher::with_options(
            secret.clone(),
            pkarr_relay.parse()?,
            ttl.as_secs().try_into()?,
            republish_interval,
        ));
        let resolver = match resolver_mode {
            ResolverMode::Pkarr => {
                Box::new(PkarrResolver::new(pkarr_relay.parse()?)) as Box<dyn Discovery>
            }
            ResolverMode::Dns => Box::new(DnsDiscovery::new(dns_origin)),
        };
        let discovery = ConcurrentDiscovery::from_services(vec![publisher, resolver]);
        let builder = MagicEndpoint::builder()
            .secret_key(secret)
            .alpns(vec![alpn.clone()])
            .discovery(Box::new(discovery));
        let builder = if let Some(relay_map) = relay_map {
            builder.relay_mode(RelayMode::Custom(relay_map))
        } else {
            builder.relay_mode(RelayMode::Disabled)
        };
        let endpoint = builder.bind().await?;
        if let Some(handler) = handler {
            tokio::spawn(server(endpoint.clone(), handler));
        }
        Ok(Self { alpn, endpoint })
    }

    pub fn peer_id(&self) -> PeerId {
        self.endpoint.node_id()
    }

    pub async fn addr(&self) -> Result<NodeAddr> {
        Ok(self.endpoint.node_addr().await?)
    }

    pub fn add_address(&self, address: NodeAddr) -> Result<()> {
        self.endpoint.add_node_addr(address)?;
        Ok(())
    }

    pub async fn resolve(&self, peer_id: PeerId) -> Result<AddrInfo> {
        Ok(self
            .endpoint
            .discovery()
            .unwrap()
            .resolve(self.endpoint.clone(), peer_id)
            .unwrap()
            .next()
            .await
            .unwrap()?
            .addr_info)
    }

    pub async fn connect(&self, peer_id: PeerId) -> Result<Connection> {
        Ok(self
            .endpoint
            .connect_by_node_id(peer_id, &self.alpn)
            .await?)
    }

    pub async fn notify<P: Protocol>(&self, peer_id: PeerId, msg: &P::Request) -> Result<()> {
        let mut conn = self.connect(peer_id).await?;
        crate::protocol::notify::<P>(&mut conn, msg).await
    }

    pub async fn request<P: Protocol>(
        &self,
        peer_id: PeerId,
        msg: &P::Request,
    ) -> Result<P::Response> {
        let mut conn = self.connect(peer_id).await?;
        crate::protocol::request_response::<P>(&mut conn, msg).await
    }

    pub async fn subscribe<P: Protocol>(
        &self,
        peer_id: PeerId,
        msg: &P::Request,
    ) -> Result<Subscription<P::Response>> {
        let mut conn = self.connect(peer_id).await?;
        crate::protocol::subscribe::<P>(&mut conn, msg).await
    }
}

async fn server(endpoint: MagicEndpoint, handler: ProtocolHandler) {
    loop {
        let Some(conn) = endpoint.accept().await else {
            tracing::info!("socket closed");
            break;
        };
        let accept_conn = move || async {
            let conn = conn.await?;
            let node_id = iroh_net::endpoint::get_remote_node_id(&conn)?;
            Result::<_, anyhow::Error>::Ok((node_id, conn))
        };
        match accept_conn().await {
            Ok((peer_id, conn)) => {
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

    async fn wait_for_addr(endpoint: &Endpoint) -> Result<NodeAddr> {
        loop {
            let addr = endpoint.addr().await?;
            if addr.info.direct_addresses.is_empty() {
                tracing::info!("waiting for publish");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            return Ok(addr);
        }
    }

    async fn wait_for_resolve(endpoint: &Endpoint) -> Result<NodeAddr> {
        loop {
            let addr = wait_for_addr(endpoint).await?;
            let Ok(resolved_addr) = endpoint.resolve(endpoint.peer_id()).await else {
                tracing::info!("waiting for publish");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            };
            if addr.info != resolved_addr {
                tracing::info!("waiting for publish");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            return Ok(addr);
        }
    }

    /*#[tokio::test]
    async fn mdns() -> Result<()> {
        env_logger::try_init().ok();

        let mut builder = Endpoint::builder(ALPN.to_vec());
        builder.enable_mdns();
        let e1 = builder.build().await?;
        let p1 = e1.peer_id();

        let mut builder = Endpoint::builder(ALPN.to_vec());
        builder.enable_mdns();
        let e2 = builder.build().await?;

        let a1_2 = wait_for_resolve(&e2, &p1).await?;
        tracing::info!("resolved {:?}", a1_2);

        let a1 = e1.addr().await?;
        assert_eq!(a1.info, a1_2);
        Ok(())
    }*/

    #[tokio::test]
    async fn pkarr() -> Result<()> {
        env_logger::try_init().ok();

        let mut builder = Endpoint::builder(ALPN.to_vec());
        builder.relay_map(None);
        let e1 = builder.build().await?;
        wait_for_resolve(&e1).await?;
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

        let a1 = wait_for_addr(&e1).await?;

        e2.add_address(a1)?;
        e2.notify::<PingPong>(p1, &Ping(42)).await?;
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

        let a1 = wait_for_addr(&e1).await?;

        e2.add_address(a1)?;
        let pong = e2.request::<PingPong>(p1, &Ping(42)).await?;
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

        let a1 = wait_for_addr(&e1).await?;

        e2.add_address(a1)?;
        let mut subscription = e2.subscribe::<PingPong>(p1, &Ping(42)).await?;
        while let Some(pong) = subscription.next().await? {
            assert_eq!(pong.0, 42);
        }
        Ok(())
    }
}

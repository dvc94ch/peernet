use crate::{Connection, PeerId, RecvStream, SendStream};
use anyhow::{Context, Result};
use futures::channel::{mpsc, oneshot};
use futures::{FutureExt, StreamExt};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::io;
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub trait Protocol: Send + Sync + 'static {
    const ID: u16;
    const REQ_BUF: usize;
    const RES_BUF: usize;
    type Request: Serialize + DeserializeOwned + Send + Sync + 'static;
    type Response: Serialize + DeserializeOwned + Send + Sync + 'static;
}

async fn send_request<P: Protocol>(tx: &mut SendStream, req: &P::Request) -> Result<()> {
    tx.write_u16(P::ID).await?;
    let bytes = bincode::serialize(req)?;
    tx.write_all(&bytes).await?;
    tx.finish().await?;
    Ok(())
}

async fn recv_request<P: Protocol>(rx: &mut RecvStream) -> Result<P::Request> {
    let buf = rx.read_to_end(P::REQ_BUF).await?;
    Ok(bincode::deserialize(&buf)?)
}

pub async fn notify<P: Protocol>(conn: &mut Connection, req: &P::Request) -> Result<()> {
    let mut tx = conn.open_uni().await?;
    send_request::<P>(&mut tx, req).await
}

pub async fn request_response<P: Protocol>(
    conn: &mut Connection,
    req: &P::Request,
) -> Result<P::Response> {
    let (mut tx, mut rx) = conn.open_bi().await?;
    send_request::<P>(&mut tx, req).await?;
    let buf = rx.read_to_end(P::RES_BUF).await?;
    Ok(bincode::deserialize(&buf)?)
}

pub async fn subscribe<P: Protocol>(
    conn: &mut Connection,
    req: &P::Request,
) -> Result<Subscription<P::Response>> {
    let (mut tx, rx) = conn.open_bi().await?;
    send_request::<P>(&mut tx, req).await?;
    Ok(Subscription::new(rx, P::RES_BUF))
}

pub struct Subscription<T> {
    _marker: PhantomData<T>,
    rx: RecvStream,
    buf: Vec<u8>,
}

impl<T: DeserializeOwned> Subscription<T> {
    pub fn new(rx: RecvStream, capacity: usize) -> Self {
        Self {
            _marker: PhantomData,
            rx,
            buf: Vec::with_capacity(capacity),
        }
    }

    pub async fn next(&mut self) -> Result<Option<T>> {
        let len = match self.rx.read_u16().await {
            Ok(len) => len,
            Err(err) => {
                return if err.kind() == io::ErrorKind::UnexpectedEof {
                    Ok(None)
                } else {
                    Err(err.into())
                };
            }
        };
        self.buf.clear();
        (&mut self.rx)
            .take(len as _)
            .read_to_end(&mut self.buf)
            .await?;
        Ok(Some(bincode::deserialize(&self.buf)?))
    }
}

pub trait NotificationHandler<P: Protocol>: Send + Sync + 'static {
    fn notify(&self, peer_id: PeerId, notification: P::Request) -> Result<()>;
}

pub trait RequestHandler<P: Protocol>: Send + Sync + 'static {
    fn request(
        &self,
        peer_id: PeerId,
        request: P::Request,
        response: oneshot::Sender<P::Response>,
    ) -> Result<()>;
}

pub trait SubscriptionHandler<P: Protocol>: Send + Sync + 'static {
    fn subscribe(
        &self,
        peer_id: PeerId,
        request: P::Request,
        response: mpsc::Sender<P::Response>,
    ) -> Result<()>;
}

struct GenericNotificationHandler<P, H> {
    _marker: PhantomData<P>,
    handler: H,
}

impl<P, H> GenericNotificationHandler<P, H>
where
    P: Protocol,
    H: NotificationHandler<P>,
{
    pub fn new(handler: H) -> Box<dyn BoxedNotificationHandler> {
        Box::new(Self {
            _marker: PhantomData,
            handler,
        })
    }
}

#[async_trait::async_trait]
trait BoxedNotificationHandler: Send + Sync + 'static {
    async fn handle(&self, peer_id: PeerId, mut rx: RecvStream) -> Result<()>;
}

#[async_trait::async_trait]
impl<P, H> BoxedNotificationHandler for GenericNotificationHandler<P, H>
where
    P: Protocol,
    H: NotificationHandler<P>,
{
    async fn handle(&self, peer_id: PeerId, mut rx: RecvStream) -> Result<()> {
        let req = recv_request::<P>(&mut rx).await?;
        self.handler.notify(peer_id, req)?;
        Ok(())
    }
}

struct GenericRequestHandler<P, H> {
    _marker: PhantomData<P>,
    handler: H,
}

impl<P, H> GenericRequestHandler<P, H>
where
    P: Protocol,
    H: RequestHandler<P>,
{
    pub fn new(handler: H) -> Box<dyn BoxedRequestHandler> {
        Box::new(Self {
            _marker: PhantomData,
            handler,
        })
    }
}

#[async_trait::async_trait]
trait BoxedRequestHandler: Send + Sync + 'static {
    async fn handle(&self, peer_id: PeerId, mut rx: RecvStream, mut tx: SendStream) -> Result<()>;
}

#[async_trait::async_trait]
impl<P, H> BoxedRequestHandler for GenericRequestHandler<P, H>
where
    P: Protocol,
    H: RequestHandler<P>,
{
    async fn handle(&self, peer_id: PeerId, mut rx: RecvStream, mut tx: SendStream) -> Result<()> {
        let req = recv_request::<P>(&mut rx).await?;
        let (htx, hrx) = oneshot::channel();
        self.handler.request(peer_id, req, htx)?;
        let res = hrx.await?;
        let bytes = bincode::serialize(&res)?;
        tx.write_all(&bytes).await?;
        tx.finish().await?;
        Ok(())
    }
}

struct GenericSubscriptionHandler<P, H> {
    _marker: PhantomData<P>,
    handler: H,
}

impl<P, H> GenericSubscriptionHandler<P, H>
where
    P: Protocol,
    H: SubscriptionHandler<P>,
{
    pub fn new(handler: H) -> Box<dyn BoxedSubscriptionHandler> {
        Box::new(Self {
            _marker: PhantomData,
            handler,
        })
    }
}

#[async_trait::async_trait]
trait BoxedSubscriptionHandler: Send + Sync + 'static {
    async fn handle(&self, peer_id: PeerId, mut rx: RecvStream, mut tx: SendStream) -> Result<()>;
}

#[async_trait::async_trait]
impl<P, H> BoxedSubscriptionHandler for GenericSubscriptionHandler<P, H>
where
    P: Protocol,
    H: SubscriptionHandler<P>,
{
    async fn handle(&self, peer_id: PeerId, mut rx: RecvStream, mut tx: SendStream) -> Result<()> {
        let req = recv_request::<P>(&mut rx).await?;
        let (htx, mut hrx) = mpsc::channel(1);
        self.handler.subscribe(peer_id, req, htx)?;
        while let Some(res) = hrx.next().await {
            let bytes = bincode::serialize(&res)?;
            tx.write_u16(bytes.len().try_into()?).await?;
            tx.write_all(&bytes).await?;
        }
        tx.finish().await?;
        Ok(())
    }
}

enum BiHandler {
    Request(Box<dyn BoxedRequestHandler>),
    Subscription(Box<dyn BoxedSubscriptionHandler>),
}

impl BiHandler {
    async fn handle(&self, peer_id: PeerId, rx: RecvStream, tx: SendStream) -> Result<()> {
        match self {
            Self::Request(handler) => handler.handle(peer_id, rx, tx).await,
            Self::Subscription(handler) => handler.handle(peer_id, rx, tx).await,
        }
    }
}

struct InnerProtocolHandler {
    uni_handlers: HashMap<u16, Box<dyn BoxedNotificationHandler>>,
    bi_handlers: HashMap<u16, BiHandler>,
}

impl InnerProtocolHandler {
    async fn new_uni(&self, peer_id: PeerId, mut rx: RecvStream) -> Result<()> {
        let protocol = rx.read_u16().await?;
        let handler = self
            .uni_handlers
            .get(&protocol)
            .context("unknown notification protocol")?;
        handler.handle(peer_id, rx).await
    }

    async fn new_bi(&self, peer_id: PeerId, mut rx: RecvStream, tx: SendStream) -> Result<()> {
        let protocol = rx.read_u16().await?;
        let handler = self
            .bi_handlers
            .get(&protocol)
            .context("unknown bi protocol")?;
        handler.handle(peer_id, rx, tx).await
    }
}

#[derive(Clone)]
pub struct ProtocolHandler(Arc<InnerProtocolHandler>);

impl ProtocolHandler {
    pub fn builder() -> ProtocolHandlerBuilder {
        ProtocolHandlerBuilder::default()
    }

    pub fn handle(&self, peer_id: PeerId, conn: Connection) {
        let handler = self.0.clone();
        tokio::spawn(async move {
            loop {
                futures::select! {
                    uni = conn.accept_uni().fuse() => {
                        let rx = match uni {
                            Ok(rx) => rx,
                            Err(err) => {
                                dbg!(err);
                                continue;
                            }
                        };
                        let handler = handler.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handler.new_uni(peer_id, rx).await {
                                dbg!(err);
                            }
                        });
                    }
                    bi = conn.accept_bi().fuse() => {
                        let (tx, rx) = match bi {
                            Ok((tx, rx)) => (tx, rx),
                            Err(err) => {
                                dbg!(err);
                                continue;
                            }
                        };
                        let handler = handler.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handler.new_bi(peer_id, rx, tx).await {
                                dbg!(err);
                            }
                        });
                    }
                }
            }
        });
    }
}

#[derive(Default)]
pub struct ProtocolHandlerBuilder {
    uni_handlers: HashMap<u16, Box<dyn BoxedNotificationHandler>>,
    bi_handlers: HashMap<u16, BiHandler>,
}

impl ProtocolHandlerBuilder {
    pub fn register_notification_handler<P: Protocol, H: NotificationHandler<P>>(
        &mut self,
        handler: H,
    ) -> &mut Self {
        self.uni_handlers
            .insert(P::ID, GenericNotificationHandler::new(handler));
        self
    }

    pub fn register_request_handler<P: Protocol, H: RequestHandler<P>>(
        &mut self,
        handler: H,
    ) -> &mut Self {
        self.bi_handlers.insert(
            P::ID,
            BiHandler::Request(GenericRequestHandler::new(handler)),
        );
        self
    }

    pub fn register_subscription_handler<P: Protocol, H: SubscriptionHandler<P>>(
        &mut self,
        handler: H,
    ) -> &mut Self {
        self.bi_handlers.insert(
            P::ID,
            BiHandler::Subscription(GenericSubscriptionHandler::new(handler)),
        );
        self
    }

    pub fn build(self) -> ProtocolHandler {
        ProtocolHandler(Arc::new(InnerProtocolHandler {
            uni_handlers: self.uni_handlers,
            bi_handlers: self.bi_handlers,
        }))
    }
}

# P2P
A p2p networking library

- transport: [quinn](https://github.com/quinn-rs/quinn)
- hole punching and relaying: [iroh-net](https://github.com/n0-computer/iroh)
- dht: [pkarr](https://github.com/nuhvi/pkarr)
- mdns: [simple-mdns](https://github.com/balliegojr/simple-dns)

## Example
```rust
const ALPN: &[u8] = b"/p2p/ping/1";

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

let mut builder = ProtocolHandler::builder();
builder.register_request_handler(PingPong);
let handler = builder.build();

let mut builder = Endpoint::builder(ALPN.to_vec());
builder.handler(handler);
let endpoint = builder.build().await?;
let pong = endpoint.request::<PingPong>(&peer, &Ping(42)).await?;
assert_eq!(pong.0, 42);
```

## License
Apache-2.0 + MIT
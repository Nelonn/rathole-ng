# Security

By default, `rathole` forwards traffic as it is. Encryption can be enabled using the **Noise Protocol Framework**.

## Noise Protocol

The [Noise Protocol](http://noiseprotocol.org/noise.html) is a lightweight, easy to configure, and drop-in replacement for TLS. It provides strong encryption and authentication without the need for self-signed certificates or CAs.

### Quickstart

`rathole` uses the **Noise IK** pattern by default, which provides server authentication (like TLS) but with much simpler configuration.

#### 1. Generate Keys
Run `rathole --genkey` to generate a keypair:

```sh
$ rathole --genkey
Noise Keypair (Pattern: IK)
---------------------------
Private Key: cQ/vwIqNPJZmuM/OikglzBo/+jlYGrOt9i0k5h5vn1Q=
Public Key:  GQYTKSbWLBUSZiGfdWPSgek9yoOuaiwGD/GIX8Z1kkE=
---------------------------
```

#### 2. Configure Server
Put the **Private Key** in your server configuration.

```toml
[server.transport.noise]
local_private_key = "SERVER_PRIVATE_KEY"
```

#### 3. Configure Client
Put the **Server's Public Key** in your client configuration.

```toml
[client.transport.noise]
remote_public_key = "SERVER_PUBLIC_KEY"
```

### Handshake Hardening (Optional)

You can further harden the handshake using a **Pre-Shared Key (PSK)** or your existing **Token**.

*   **Automatic Token-to-PSK**: If you define a `token` for a user/client, `rathole` will automatically hash it and use it as a Noise PSK to "encrypt" the handshake.
*   **Manual PSK**: You can also specify an explicit PSK in the `[transport.noise]` block:
    ```toml
    psk = "psk_encoded_in_base64"
    ```

### Transports

The Noise layer can be applied to both **TCP** and **UDP** transports.

```toml
[client.transport]
type = "udp" # or "tcp"

[client.transport.noise]
remote_public_key = "..."
```

## Transport Options

### TCP

Custom options for the TCP layer:

```toml
[client.transport.tcp]
nodelay = true      # Enable TCP_NODELAY
keepalive_secs = 20 # TCP keepalive time
proxy = "socks5://..." # Connect via a proxy
```

### UDP

The UDP transport in `rathole` includes a custom reliability layer with **Anti-DPI** padding.

```toml
[client.transport.udp]
psk = "rathole" # Shared secret for the UDP reliability layer
```

# rathole

![rathole-logo](./docs/img/rathole-logo.png)

[![GitHub stars](https://img.shields.io/github/stars/rapiz1/rathole)](https://github.com/rapiz1/rathole/stargazers)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/rapiz1/rathole)](https://github.com/rapiz1/rathole/releases)
![GitHub Workflow Status (branch)](https://img.shields.io/github/actions/workflow/status/rapiz1/rathole/rust.yml?branch=main)
[![GitHub all releases](https://img.shields.io/github/downloads/rapiz1/rathole/total)](https://github.com/rapiz1/rathole/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/rapiz1/rathole)](https://hub.docker.com/r/rapiz1/rathole)
[![Join the chat at https://gitter.im/rapiz1/rathole](https://badges.gitter.im/rapiz1/rathole.svg)](https://gitter.im/rapiz1/rathole?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

[English](README.md) | [简体中文](README-zh.md)

A secure, stable and high-performance reverse proxy for NAT traversal, written in Rust

rathole, like [frp](https://github.com/fatedier/frp) and [ngrok](https://github.com/inconshreveable/ngrok), can help to expose the service on the device behind the NAT to the Internet, via a server with a public IP.

<!-- TOC -->

- [rathole](#rathole)
  - [Features](#features)
- [Quickstart](#quickstart)
  - [Configuration](#configuration)
    - [Logging](#logging)
    - [Tuning](#tuning)
  - [Benchmark](#benchmark)
  - [Planning](#planning)

<!-- /TOC -->

## Features

- **High Performance** Much higher throughput can be achieved than frp, and more stable when handling a large volume of connections. See [Benchmark](#benchmark)
- **Low Resource Consumption** Consumes much fewer memory than similar tools. See [Benchmark](#benchmark). [The binary can be](docs/build-guide.md) **as small as ~500KiB** to fit the constraints of devices, like embedded devices as routers.
- **Security** Users and tokens are used for authentication. With the optional Noise Protocol, encryption can be configured at ease. No need to create a self-signed certificate! TLS is also supported.
- **Hot Reload** Services can be added or removed dynamically by hot-reloading the configuration file. HTTP API is WIP.

## Quickstart

A full-powered `rathole` can be obtained from the [release](https://github.com/rapiz1/rathole/releases) page. Or [build from source](docs/build-guide.md) **for other platforms and minimizing the binary**. A [Docker image](https://hub.docker.com/r/rapiz1/rathole) is also available.

Assuming you have a NAS at home behind the NAT, and want to expose its ssh service to the Internet:

1. On the server which has a public IP

Create `server.toml`:

```toml
[server]
bind_addr = "0.0.0.0:2333"

[server.users.default] # Define a user
token = "my_secret_token" # Optional password

[server.services.my_nas_ssh]
user = "default"
bind_addr = "0.0.0.0:5202"
```

2. On the host which is behind the NAT (your NAS)

Create `client.toml`:

```toml
[client]
remote_addr = "myserver.com:2333"
user = "default"
token = "my_secret_token"

[client.services.my_nas_ssh]
local_addr = "127.0.0.1:22"
```

Then run `rathole server.toml` on the server and `rathole client.toml` on the client.

### Visitor Mode (FRP-style)

`rathole` supports a "Visitor Mode" where the client can request the server to bind to a specific address/port.

**Server Configuration:**

1. Run `rathole --genkey` to get your server's identity.
2. Configure `server.toml`:

```toml
[server]
bind_addr = "0.0.0.0:2333"

[server.transport]
type = "udp"
[server.transport.noise]
local_private_key = "SERVER_PRIVATE_KEY_HERE"

[server.users.alice]
token = "alice_token"
allowed_ports = "2000-3000" # Alice can bind to these ports
```

**Client Configuration:**

```toml
[client]
remote_addr = "myserver.com:2333"
user = "alice"
token = "alice_token"

[client.transport]
type = "udp"
[client.transport.noise]
remote_public_key = "SERVER_PUBLIC_KEY_HERE"

[client.services.my_service]
local_addr = "127.0.0.1:8080"
remote_bind_addr = "0.0.0.0:2334"
```

### Docker

```yaml
  rathole:
    image: ghcr.io/nelonn/rathole-ng:nightly
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./rathole-config.toml:/rathole-config.toml
```

## Configuration

```toml
[client]
remote_addr = "example.com:2333"
user = "default" # Default user for services
token = "test_token" # Default token for services

[client.transport]
type = "udp" # Possible values: ["tcp", "udp"]

[client.transport.noise] # Noise protocol layer
pattern = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
remote_public_key = "SERVER_PUBLIC_KEY"
psk = "optional_transport_psk"

[client.services.service1]
local_addr = "127.0.0.1:1081"
# user and token can be overridden here

[server]
bind_addr = "0.0.0.0:2333"

[server.users.alice]
token = "alice_token"
allowed_ports = "2000-3000"

[server.transport]
type = "udp"

[server.transport.noise]
local_private_key = "SERVER_PRIVATE_KEY"

[server.services.service1]
user = "alice"
bind_addr = "0.0.0.0:8081"
```

## Benchmark

![http_throughput](./docs/img/http_throughput.svg)
![tcp_bitrate](./docs/img/tcp_bitrate.svg)
![udp_bitrate](./docs/img/udp_bitrate.svg)
![mem](./docs/img/mem-graph.png)

# nazoauth

Embed OAuth 2.0 and OpenID Connect in a Rust host using the framework-neutral
`NazoAuth` service and `NazoAuthBuilder`. The host supplies storage, keys and
transport. The library owns protocol processing and requires Rust 1.100 or later.

```sh
cargo add nazoauth
```

For a host that does not expose deployment control, use
`cargo add nazoauth --no-default-features`.

The [Rust embedding guide](https://github.com/nazozero/NazoAuth/blob/main/docs/integration/rust-embedding.md)
describes host configuration, service construction and HTTP integration.

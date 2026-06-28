# voprf-ng ![Build Status](https://github.com/raphaelrobert/voprf-ng/workflows/Rust%20CI/badge.svg)
An implementation of a (verifiable) oblivious pseudorandom function (VOPRF)

A VOPRF is a verifiable oblivious pseudorandom function, a protocol between a client and a server. The regular (non-verifiable) OPRF is also supported in this implementation.

This implementation is based on [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497).

`voprf-ng` is a fork of [`voprf`](https://github.com/facebook/voprf) by Kevin Lewi.

Documentation
-------------

The API can be found [here](https://docs.rs/voprf-ng/) along with an example for usage.

Installation
------------

Add the following line to the dependencies of your `Cargo.toml`:

```
voprf-ng = "0.6.0-pre.2"
```

### Minimum Supported Rust Version

Rust **1.85** or higher.

Contributors
------------

To learn more about contributing to this project, [see this document](./CONTRIBUTING.md).

License
-------

This project is dual-licensed under either the [MIT license](./LICENSE-MIT)
or the [Apache License, Version 2.0](./LICENSE-APACHE).
You may select, at your option, one of the above-listed licenses.

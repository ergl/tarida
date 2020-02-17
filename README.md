# Tarida

Tarida is an (in progress) minimal [SSB](https://scuttlebutt.nz) server, written in [Pony](https://www.ponylang.io).

## Roadmap

Not much planned right now. My first intention was to experiment with the SSB protocol. We'll see how it goes!

### What's implemented?

- Local network peer advertisement and discovery.
- Secret Handshake protocol.

### What's next?

- Box stream protocol (although key derivation is complete).
- RPC protocol.
- Feeds (although probably using the [GabbyGrove](https://github.com/ssbc/ssb-spec-drafts/blob/b9187d5e11e5d630e4485af8e44f08f2afab6c08/drafts/draft-ssb-core-gabbygrove/00/draft-ssb-core-gabbygrove-00.md) format).
- Figure out how to do static binaries for linux, at least.
- Identity persistence between runs (right now, tarida generates a new identity pair every time it's run).
- Command line configuration (server/client mode, configuration folder, etc).

## Build

Disclaimer: I've only been hacking on tarida in my free time, so I haven't put any effort on making it easy to install (sorry!). If I have time, I'll figure out how to build static binaries so users don't have to build tarida from source.

Tarida only works on OSX for now, although only for the lack of effort. Tarida depends on `libsodium` for the secret handshake protocol. To build tarida, first install libsodium, the [Pony](https://github.com/ponylang/ponyc/blob/295f65cb2330606c4f0697bfdf20aa51e61034cf/INSTALL.md) compiler, and the [`pony-stable`](https://github.com/ponylang/pony-stable) dependency manager.

After cloning the repo, download the dependencies with `stable fetch`, and then `make`. To run it, do `./_build/tarida`. A debug version can be built with `make debug`, and executed with `./_build/debug_tarida`.

The tests can be run with `make tests`. Integration tests for the secret handshake protocol can be built with `make integration`. This will build a `shs_tarida` binary under the `_build` folder that you can use with [`shs1-test`](https://github.com/AljoschaMeyer/shs1-test) to run the tests.

## Why Tarida?

A _tarida_ was a small boat used to transport horses in Catalonia during the 14th century. In keeping with the tradition of naming SSB-related projects after nautical names, I decided to merge this tradition with an equine theme, after the programming language used for this project, Pony.

## License

Tarida is licensed under the MIT license. For more information, check out the [license](./LICENSE).

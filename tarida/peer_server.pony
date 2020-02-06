use "net"
use "shs"
use "sodium"
use "debug"

// SHS/RPC Ideas:
// On starting, our TCP server uses a Handshake notify, that performs the SHS mechanism.
// When/if the handshake succeeds, it changes the notify: the new one is a nested notify.
// The outter layer performs the box stream framing and enc/decryption.
// The next layer is the RPC mechanism, which also handles framing.
// The RPC layer can either be the final layer, or delegate RPC header parsing to another notifier.

// Consider doing SHS inside notify, instead of using
// a different actor. This way, when we finish the SHS,
// we can set a new notify, and pass all the derived keys
// from it. With an actor server, we don't know its lifetime
// after the SHS has finished.

class iso _PeerNotify is TCPConnectionNotify
  let _shs: HandshakeServer
  new iso create(h: HandshakeServer) =>
    _shs = consume h

  fun ref accepted(conn: TCPConnection ref) =>
    // Create ephemeral keys on connection
    try conn.expect(_shs.init()?)? else conn.close() end

  fun ref received(
    conn: TCPConnection ref,
    data: Array[U8] iso,
    times: USize)
    : Bool
  =>
    let msg = String.from_iso_array(consume data)
    try
      (let expect, let resp) = _shs.step(consume msg)?
      if expect == 0 then
        // TODO(borja): Swap notify
        Debug.out("Handshake complete")
      end

      conn.write(resp)
      conn.expect(expect)?
    else
      Debug.err("Error: _PeerNotify bad SHS")
      conn.close()
    end

    true

  fun ref closed(conn: TCPConnection ref) =>
    Debug.out("_PeerNotify closed")

  fun ref connect_failed(conn: TCPConnection ref) =>
    None

class iso _PeerListenNotify is TCPListenNotify
  let _pk: Ed25519Public
  let _sk: Ed25519Secret

  new iso create(pk: Ed25519Public, sk: Ed25519Secret) =>
    (_pk, _sk) = (pk, sk)

  fun ref listening(listen: TCPListener ref) =>
    try
      (let addr, let port) = listen.local_address().name()?
      Debug.out("_PeerListenNotify listening on " + addr + ":" + port)
    end

  fun ref connected(
    listen: TCPListener ref)
    : TCPConnectionNotify iso^
  =>
    Debug.out("_PeerListenNotify connected")
    _PeerNotify(HandshakeServer(_pk, _sk, DefaultNetworkId()))

  fun ref not_listening(listen: TCPListener ref) =>
    Debug.err("_PeerListenNotify not_listening")
    None

actor PeerServer
  new create(
    auth: NetAuth,
    pk: Ed25519Public,
    sk: Ed25519Secret,
    port: String)
  =>
    TCPListener(
      auth,
      _PeerListenNotify(pk, sk),
      "",
      port)

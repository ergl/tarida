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

primitive _BoxStreamExpectHeader
class val _BoxStreamExpectBody
  let auth_tag: String
  new val create(other_tag: String) =>
    auth_tag = other_tag

type _BoxStreamNotifyState is (_BoxStreamExpectHeader | _BoxStreamExpectBody)

class iso _BoxStreamNotify is TCPConnectionNotify
  let _boxstream: BoxStream
  var _state: _BoxStreamNotifyState

  new iso create(boxtream: BoxStream iso) =>
    _boxstream = consume boxtream
    _state = _BoxStreamExpectHeader

  fun ref connect_failed(conn: TCPConnection ref) => None

  fun ref sent(conn: TCPConnection ref, data: ByteSeq): ByteSeq =>
    // TODO(borja): Encrypt data here. Must return the transformed data
    data

  fun ref sentv(conn: TCPConnection ref, data: ByteSeqIter): ByteSeqIter =>
    // TODO(borja): Encrypt data here. Will this be used?
    data

  fun ref received(
    conn: TCPConnection ref,
    data: Array[U8] iso,
    times: USize)
    : Bool
  =>
    let msg = String.from_array(consume data)
    try
      match _state
      | _BoxStreamExpectHeader =>
        Debug.out("_BoxStreamNotify recv header of size " + msg.size().string())
        let result = _boxstream.decrypt_header(consume msg)?
        match result
        | None =>
          // goodbye
          Debug.out("Recv a goodbye")
          conn.close()

        | (let next_expect: USize, let auth_tag: String) =>
            Debug.out("_BoxStreamNotify should expect body of size " + next_expect.string())
            conn.expect(next_expect)?
            _state = _BoxStreamExpectBody(auth_tag)
        end

      | let info: _BoxStreamExpectBody =>
        let plaintext = _boxstream.decrypt(info.auth_tag, msg)?
        Debug.out("Recv plaintext: " + plaintext)

        conn.expect(_boxstream.header_size())?
        _state = _BoxStreamExpectHeader
      end

      true
    else
      conn.close()
      Debug.err("Error: _BoxStreamNotify bad recv")
      false
    end

  fun ref expect(conn: TCPConnection ref, qty: USize): USize =>
    // TODO(borja): Figure out if we must do something here
    qty

  fun ref closed(conn: TCPConnection ref) =>
    // TODO(borja): Should we send the goodbye here?
    None

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
        Debug.out("Handshake complete")
        let boxstream = _shs.boxstream()?
        conn.expect(boxstream.header_size())?
        conn.set_notify(_BoxStreamNotify(consume boxstream))
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

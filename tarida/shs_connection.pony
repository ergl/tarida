use "shs"
use "sodium"

use "net"
use "debug"

class iso _SHSNotify is TCPConnectionNotify
  let _self_pk: Ed25519Public
  let _self_sk: Ed25519Secret
  let _target_pk: (Ed25519Public | None)
  let _shs: (HandshakeServer | HandshakeClient)

  new iso server(pk: Ed25519Public, sk: Ed25519Secret, shs: HandshakeServer iso) =>
    _self_pk = pk
    _self_sk = sk
    _target_pk = None
    _shs = consume ref shs

  new iso client(pk: Ed25519Public, sk: Ed25519Secret, other_pk: Ed25519Public, shs: HandshakeClient iso) =>
    _self_pk = pk
    _self_sk = sk
    _target_pk = other_pk
    _shs = consume ref shs

    fun ref connect_failed(conn: TCPConnection ref) =>
      Debug.out("_SHSNotify closed")

    fun ref closed(conn: TCPConnection ref) =>
      Debug.out("_SHSNotify closed")

  fun ref accepted(conn: TCPConnection ref) =>
    match _shs
    | let c: HandshakeClient => None
    | let s: HandshakeServer =>
      // Create ephemeral keys on connection
      try
        conn.expect(s.init()?)?
      else
        Debug.err("_SHSNotify/server couldn't init")
        conn.close()
      end
    end

  fun ref connected(conn: TCPConnection ref) =>
    match _shs
    | let s: HandshakeServer => None
    | let c: HandshakeClient =>
      try
        // Create ephemeral keys, send client hello
        (let expect, let cl_hello) = c.step("")?
        conn.write_final(cl_hello)
        conn.expect(expect)?
      else
        Debug.err("_SHSNotify/client couldn't init")
        conn.close()
      end
    end

  fun ref _handle_done(
    conn: TCPConnection ref,
    remote_pk: Ed25519Public,
    bx: BoxStream iso)
  =>

    let notify = _BoxStreamNotify(
      recover tag conn end,
      _self_pk,
      _self_sk,
      remote_pk,
      consume bx
    )
    conn.set_notify(consume notify)

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
        match _shs
        | let c: HandshakeClient =>
            _handle_done(conn, _target_pk as Ed25519Public, consume boxstream)
        | let s: HandshakeServer =>
            let remote_pk = s.remote_pk()?
            conn.write_final(resp) // Send server accept
            _handle_done(conn, remote_pk, consume boxstream)
        end
      else
        conn.expect(expect)?
        conn.write_final(resp)
      end
    else
      Debug.err("_SHSNotify: bad SHS")
      conn.close()
    end

    true

class _SHSListenNotify is TCPListenNotify
  let _pk: Ed25519Public
  let _sk: Ed25519Secret

  new iso create(pk: Ed25519Public, sk: Ed25519Secret) =>
    (_pk, _sk) = (pk, sk)

  fun ref listening(listen: TCPListener ref) =>
    try
      (let addr, let port) = listen.local_address().name()?
      Debug.out("_SHSListenNotify listening on " + addr + ":" + port)
    end

  fun ref connected(listen: TCPListener ref): TCPConnectionNotify iso^ =>
    Debug.out("_SHSListenNotify connected")
    _SHSNotify.server(_pk, _sk, HandshakeServer(_pk, _sk, DefaultNetworkId()))

  fun ref not_listening(listen: TCPListener ref) =>
    Debug.err("_SHSListenNotify not_listening")
    None

primitive Handshake
  fun server(
    auth: AmbientAuth,
    pk: Ed25519Public,
    sk: Ed25519Secret,
    port: String)
    : TCPListener
  =>
    TCPListener(NetAuth(auth), _SHSListenNotify(pk, sk), "", port)

  fun client(
    auth: AmbientAuth,
    pk: Ed25519Public,
    sk: Ed25519Secret,
    target_pk: Ed25519Public,
    target_ip: String,
    target_port: String)
    : None
  =>

    let notify = _SHSNotify.client(
      pk,
      sk,
      target_pk,
      HandshakeClient(pk, sk, target_pk, DefaultNetworkId())
    )

    TCPConnection(NetAuth(auth), consume notify, target_ip, target_port)

use "net"
use "debug"
use "sodium"

class iso _PeerNotify is TCPConnectionNotify
  let _h: _HandshakeServer
  new iso create(h: _HandshakeServer) => _h = h

  fun ref accepted(conn: TCPConnection ref) =>
    _h.ready(recover tag conn end)

  fun ref received(
    conn: TCPConnection ref,
    data: Array[U8] iso,
    times: USize)
    : Bool
  =>
    _h.step(String.from_iso_array(consume data))
    true

  fun ref connect_failed(conn: TCPConnection ref) =>
    None

class iso _PeerListenNotify is TCPListenNotify
  let _h: _HandshakeServer
  new iso create(h: _HandshakeServer) => _h = h

  fun ref listening(listen: TCPListener ref) =>
    try
      (let addr, let port) = listen.local_address().name()?
      Debug.out("_PeerListenNotify listening on " + addr + ":" + port)
    end

  fun ref connected(listen: TCPListener ref): TCPConnectionNotify iso^ =>
    Debug.out("_PeerListenNotify connected")
    _PeerNotify(_h)

  fun ref not_listening(listen: TCPListener ref) =>
    Debug.err("_PeerListenNotify not_listening")
    None

primitive _ClientHello
primitive _ClientAuth
type _ServerFSM is (_ClientHello | _ClientAuth)

primitive _ServerHello
primitive _ServerAccept
type _ClientFSM is (_ServerHello | _ServerAccept)

actor _HandshakeServer
  let _self_pk: Ed25519Public
  let _self_sk: Ed25519Secret

  var _h: (Handshake | None) = None
  var _state: _ServerFSM = _ClientHello
  var _socket: (TCPConnection | None) = None

  new create(pk: Ed25519Public, sk: Ed25519Secret) =>
    _self_pk = pk
    _self_sk = sk

  be ready(socket: TCPConnection) =>
    Debug.out("_HandshakeServer ready")
    _socket = socket

  be step(msg: String) =>
    try
      match _state
      | _ClientHello =>
        _do_hello(msg)?
        Debug.out("_HandshakeServer valid client_hello")
        _state = _ClientAuth

      | _ClientAuth =>
        Debug.out("_HandshakeServer _ClientAuth?")
      end
    else
      _close()
    end

  fun ref _do_hello(msg: String)? =>
    (let eph_pk, let eph_sk) = Sodium.curve25519_pair()?
    let h = Handshake(_self_pk, _self_sk, eph_pk, eph_sk)
    if not h.hello_verify(msg) then error end

    (_socket as TCPConnection).write(h.hello_challenge()?)
    _h = h

  fun _close() =>
    try (_socket as TCPConnection).dispose() end

actor PeerServer
  let _l: TCPListener
  new create(auth: NetAuth, pk: Ed25519Public, sk: Ed25519Secret, port: String) =>
    _l = TCPListener(auth, _PeerListenNotify(_HandshakeServer(pk, sk)), "", port)

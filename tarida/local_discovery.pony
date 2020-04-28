// For local discovery, we need two things:
// - An UDP server listening on 0.0.0.0:8008, receiving advertisements
// - An UDP client listening on the private IP:XXX, sending advertisements
// The above client needs to advertise our TCP server, listening on 0.0.0.0:XXX

use "net"
use "time"
use "regex"
use "collections"

use "debug"

class iso _BroadcastSenderTimer is TimerNotify
  let _discovery: Discovery

  new iso create(discovery: Discovery) =>
    _discovery = discovery

  fun ref apply(timer: Timer, count: U64): Bool =>
    _discovery._broadcast()
    true

  fun ref cancel(timer: Timer) => None

class iso _BroadcastSender is UDPNotify
  let _discovery: Discovery

  new iso create(discovery: Discovery) =>
    _discovery = discovery

  fun ref listening(sock: UDPSocket ref) =>
    sock.set_broadcast(true)
    if sock.setsockopt_u32(OSSockOpt.sol_socket(), OSSockOpt.so_reuseaddr(), 1) != 0 then
      Debug.err("Error: _BroadcastSender so_reuseaddr")
      sock.dispose()
      return
    end

    if sock.setsockopt_u32(OSSockOpt.sol_socket(), OSSockOpt.so_reuseport(), 1) != 0 then
      Debug.err("Error: _BroadcastSender so_reuseport")
      sock.dispose()
      return
    end

    _discovery._snd_sock_ready()

  fun ref received(sock: UDPSocket ref, data: Array[U8] iso, from: NetAddress) =>
    Debug.out("_BroadcastSender drop recv")
    None // Drop packets

  fun ref not_listening(sock: UDPSocket ref) =>
    Debug.err("Error: _BroadcastSender not_listening")

  fun ref closed(sock: UDPSocket ref) =>
    Debug.out("_BroadcastSender closed")

class iso _BroadcastReceiver is UDPNotify
  let _auth: DNSLookupAuth
  let _discovery: Discovery

  new iso create(auth: DNSLookupAuth, discovery: Discovery) =>
    _auth = auth
    _discovery = discovery

  fun ref not_listening(sock: UDPSocket ref) =>
    Debug.err("Error: _BroadcastReceiver not_listening")

  fun ref listening(sock: UDPSocket ref) =>
    sock.set_broadcast(true)
    if sock.setsockopt_u32(OSSockOpt.sol_socket(), OSSockOpt.so_reuseaddr(), 1) != 0 then
      Debug.err("Error: _BroadcastReceiver so_reuseaddr")
      sock.dispose()
      return
    end

    if sock.setsockopt_u32(OSSockOpt.sol_socket(), OSSockOpt.so_reuseport(), 1) != 0 then
      Debug.err("Error: _BroadcastReceiver so_reuseport")
      sock.dispose()
      return
    end

    try
      (let self_addr, let self_port) = sock.local_address().name()?
      Debug.out("_BroadcastReceiver listening on " + self_addr + ":" + self_port)
    else
      Debug.err("Error: _BroadcastReceiver local_addres name?")
      sock.dispose()
    end

  fun ref received(sock: UDPSocket ref, data: Array[U8] iso, from: NetAddress) =>
    _discovery._peer(String.from_array(consume data))

  fun ref closed(sock: UDPSocket ref) =>
    Debug.out("_BroadcastReceiver closed")

actor Discovery
  let _auth: NetAuth
  let _self_pk: String

  let _self_ip: String
  let _self_port: String
  let _peer_port: String
  var _broadcast_addr: (NetAddress | None) = None
  let _announcement: String

  let _recv_socket: UDPSocket
  let _snd_socket: UDPSocket

  let _broadcast_interval: U64 = 2_000_000_000
  let _timer_wheel: Timers = Timers
  var _timer_handle: (Timer tag | None) = None

  let _ann_regex: (Regex | None)
  let _found_peers: Set[String] = Set[String]

  new create(auth: AmbientAuth, pk: String, host: String, port: String, peer_port: String) =>
    _auth = NetAuth(auth)
    _ann_regex = try Regex("^net:(.+):(\\d+)~shs:(.+)$")? else None end
    _self_pk = pk
    _self_ip = host
    _self_port = port
    _peer_port = peer_port

    Debug.out("Discovery will advertise on " + _self_ip + ":" + _self_port)
    _snd_socket = UDPSocket(_auth, _BroadcastSender(this), _self_ip, _self_port)
    _recv_socket = UDPSocket(_auth, _BroadcastReceiver(_auth, this), "", _self_port)
    _announcement = recover val
      String.create(4 + _self_ip.size() + 1 + _peer_port.size() + 5 + _self_pk.size())
        .>append("net:")
        .>append(_self_ip)
        .>push(':')
        .>append(_peer_port)
        .>append("~shs:")
        .>append(_self_pk)
    end

  be _snd_sock_ready() =>
    try
      _broadcast_addr = DNS.broadcast_ip4(_auth, _self_port)(0)?
      let handle = Timer(_BroadcastSenderTimer(this), _broadcast_interval, _broadcast_interval)
      _timer_handle = recover tag handle end
      _timer_wheel(consume handle)
    else
      Debug.err("Error: Discover broadcast_ip4")
    end

  be _broadcast() =>
    try
      _snd_socket.write(_announcement, _broadcast_addr as NetAddress)
    end

  be _peer(maybe_ann: String) =>
    try
      let ann = maybe_ann.split(";")(0)?
      let matches = (_ann_regex as Regex)(ann)?

      let peer_ip = matches(1)?
      let peer_port = matches(2)?
      let peer_pub_iso = matches(3)?
      let peer_pub = consume val peer_pub_iso

      // Ignore self
      if (peer_pub == _self_pk) or _found_peers.contains(peer_pub) then
        return
      end

      Debug.out("Discovery found peer "
                + (consume peer_ip)
                + ":"
                + (consume peer_port)
                + "~"
                + peer_pub)

      _found_peers.set(peer_pub)
    end

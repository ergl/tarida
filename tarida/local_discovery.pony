// For local discovery, we need two things:
// - An UDP server listening on 0.0.0.0:8008, receiving advertisements
// - An UDP client listening on the private IP:XXX, sending advertisements
// The above client needs to advertise our TCP server, listening on 0.0.0.0:XXX

use "net"
use "time"
use "regex"

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

  var _self_ip: (String | None) = None
  let _self_port: String
  var _broadcast_addr: (NetAddress | None) = None
  var _announcement: (String | None) = None

  let _recv_socket: UDPSocket
  var _snd_socket: (UDPSocket | None) = None

  let _broadcast_interval: U64 = 2_000_000_000
  let _timer_wheel: Timers = Timers
  var _timer_handle: (Timer tag | None) = None

  new create(auth: AmbientAuth, iface: String, port: String, pk: String) =>
    _auth = NetAuth(auth)
    _self_port = port
    _self_pk = pk

    _recv_socket = UDPSocket(_auth, _BroadcastReceiver(_auth, this), "", port)
    IPConfig(
      auth,
      iface,
      recover val this~_iface_ready() end,
      recover val this~_iface_error() end
    )

  be _iface_ready(self_ip: String) =>
    Debug.out("Discovery will advertise on " + self_ip + ":" + _self_port)
    _self_ip = self_ip
    _snd_socket = UDPSocket(_auth, _BroadcastSender(this), self_ip, _self_port)
    _announcement = recover val
      String.create(4 + self_ip.size() + 1 + _self_port.size() + 5 + _self_pk.size())
        .>append("net:")
        .>append(self_ip)
        .>push(':')
        .>append(_self_port)
        .>append("~shs:")
        .>append(_self_pk)
    end

  be _iface_error() =>
    Debug.err("Error: Discover get_ip_error, won't advertise")

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
      (_snd_socket as UDPSocket).write((_announcement as String), _broadcast_addr as NetAddress)
    end

  be _peer(maybe_ann: String) =>
    try
      let ann_regex = Regex("^net:(.+):(\\d+)~shs:(.+)$")?
      let ann = maybe_ann.split(";")(0)?
      let matches = ann_regex(ann)?

      let peer_ip = matches(1)?
      let peer_port = matches(2)?
      let peer_pub = matches(3)?

      // Ignore self
      if peer_pub == _self_pk then
        return
      end

      Debug.out("Discovery found peer "
                + (consume peer_ip)
                + ":"
                + (consume peer_port)
                + "~"
                + (consume peer_pub))
    end

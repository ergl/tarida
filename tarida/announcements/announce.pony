use "../sodium"
use "../identity"

use "logger"
use "net"
use "time"

class iso _SendTimer is TimerNotify
  let _logger: Logger[String val]
  let _ann: Announcement

  new iso create(logger: Logger[String], ann: Announcement) =>
    _logger = logger
    _ann = ann

  fun ref apply(timer: Timer, count: U64): Bool =>
    _ann._broadcast()
    true

  fun ref cancel(timer: Timer) =>
    None

class iso _SndNotify is UDPNotify
  let _log: Logger[String val]
  let _ann: Announcement

  new iso create(log: Logger[String val], ann: Announcement) =>
    _log = log
    _ann = ann

  fun ref listening(socket: UDPSocket ref) =>
    socket.set_broadcast(true)
    if socket.setsockopt_u32(OSSockOpt.sol_socket(), OSSockOpt.so_reuseaddr(), 1) != 0 then
      _log(Error) and _log.log("Can't set so_reuseaddr")
      socket.dispose()
      return
    end

    if socket.setsockopt_u32(OSSockOpt.sol_socket(), OSSockOpt.so_reuseport(), 1) != 0 then
      _log(Error) and _log.log("Can't set so_reuseport")
      return
    end

    _ann._sock_ready()

  fun ref received(socket: UDPSocket ref, data: Array[U8] iso, from: NetAddress) =>
    _log(Info) and _log.log("Drop recv")
    // Drop all received packets
    None

  fun ref not_listening(socket: UDPSocket ref) =>
    _log(Error) and _log.log("not_listening")

  fun ref closed(socket: UDPSocket ref) =>
    _ann._sock_closed()

actor Announcement
  let _logger: Logger[String val]

  let _auth: NetAuth
  let _self_port: String
  let _socket: UDPSocket
  let _announcement: String

  var _broadcast_addr: (NetAddress | None) = None
  let _broadcast_interval: U64 = 2_000_000_000

  let _timer_wheel: Timers = Timers
  var _timer_handle: (Timer tag | None) = None

  new create(
    logger: Logger[String val],
    auth: NetAuth,
    self_pk: Ed25519Public,
    self_ip: String,
    self_port: String,
    peering_port: String)
  =>
    _logger = logger

    _auth = auth
    _self_port = self_port
    _logger(Info) and _logger.log("Trying to broadcast from " + self_ip + ":" + _self_port)
    _socket = UDPSocket(auth, _SndNotify(logger, this), self_ip, _self_port)

    let identity: String = Identity.encode(self_pk)
    _announcement = recover val
      String.create(4 + self_ip.size() + 1 + peering_port.size() + 5 + identity.size())
        .>append("net:")
        .>append(self_ip)
        .>push(':')
        .>append(peering_port)
        .>append("~shs:")
        .>append(identity)
    end

    _logger(Info) and _logger.log("Announcement is: " + _announcement)

  be _sock_ready() =>
    _logger(Info) and _logger.log("Announcement socket is ready")
    try
      let broadcast_addr = DNS.broadcast_ip4(_auth, _self_port)(0)?
      _broadcast_addr = broadcast_addr

      (let name, let service) = broadcast_addr.name()?
      _logger(Info) and _logger.log("Announcing to " + name + ":" + service)

      let handle = Timer(_SendTimer(_logger, this), _broadcast_interval, _broadcast_interval)
      _timer_handle = recover tag handle end
      _timer_wheel(consume handle)
    else
      _logger(Error) and _logger.log("Failed to get broadcast_ip4")
    end

  be _sock_closed() =>
    _logger(Error) and _logger.log("Announce socket got closed")
    _broadcast_addr = None


  be _broadcast() =>
    match _broadcast_addr
    | let addr: NetAddress =>
      _socket.write(_announcement, addr)
    else
      None
    end

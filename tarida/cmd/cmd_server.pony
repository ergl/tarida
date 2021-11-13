use "../config"
use "../announcements"
use "../sodium"
use "../boxstream"
use "../identity"
use "../shs"
use "../handlers"

use "bureaucracy"
use "files"
use "logger"
use "net"
use "signals"

class CmdServer
  fun ref apply(
    logger: Logger[String val],
    auth: AmbientAuth,
    config: Config,
    self_config: ServerConfig)
  =>
    try
      let identity = try
        Identity.from_path(FileAuth(auth), config.identity_path)?
      else
        None
      end

      if identity is None then
        logger(Error) and
          logger.log("Couldn't read identity " + config.identity_path)
        return
      end

      (let public, let secret) = identity as (Ed25519Public, Ed25519Secret)
      let custodian = Custodian
      let autoconn_custodian = if config.enable_autoconnect then
        custodian
      else
        None
      end

      if config.enable_broadcast then
        Announcement(
          logger,
          NetAuth(auth),
          public,
          self_config.self_ip,
          "8008",
          self_config.self_port)
      end

      let notify = _ServerListener.create(logger, public, secret, custodian)
      TCPListener(NetAuth(auth), consume notify, self_config.self_ip, self_config.self_port)

      _RegisterHandler.apply(custodian)
    else
      logger(Error) and logger.log("Couldn't start server")
    end

class _ServerListener is TCPListenNotify
  let _log: Logger[String val]
  let _pk: Ed25519Public
  let _sk: Ed25519Secret
  let _custodian: Custodian

  new iso create(
    logger: Logger[String val],
    pk: Ed25519Public,
    sk: Ed25519Secret,
    custodian: Custodian)
=>
    _log = logger
    (_pk, _sk) = (pk, sk)
    _custodian = custodian

  fun ref listening(listen: TCPListener ref) =>
    try
      (let addr, let port) = listen.local_address().name()?
      _log(Info) and _log.log("Server listening on " + addr + ":" + port)
    else
      _log(Error) and _log.log("Couldn't get local address")
      listen.close()
    end

  fun ref connected(listen: TCPListener): TCPConnectionNotify iso^ =>
    _log(Info) and _log.log("Server starting with SHS")
    BoxStreamConnection.server(
      _log,
      RPCNotify(
        _log,
        RPCConnectionServer(
          _log,
          _pk,
          _sk
        )
      ),
      _pk,
      _sk,
      DefaultNetworkId()
    )

  fun ref not_listening(listen: TCPListener ref) =>
    _log(Error) and _log.log("Server not listening")
    listen.close()

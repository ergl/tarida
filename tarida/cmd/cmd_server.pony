use "../config"
use "../discovery"
use "../sodium"
use "../shs"
// use "../ssb-box"
use "../identity"

use "bureaucracy"
use "logger"
use "net"
use "signals"

class CmdServer is CmdType
  fun ref apply(
    logger: Logger[String val],
    auth: AmbientAuth,
    config: Config)
  =>

    try
      let self_config = config.mode_config as ServerConfig

      // TODO(borja): Read identity from config.config_path
      (let public, let secret) = Identity.generate()?
      let custodian = Custodian
      let autoconn_custodian = if config.enable_autoconnect then
        custodian
      else
        None
      end

      if config.enable_discovery then
        Discovery(auth, public, secret, self_config.self_ip, "8008",
          self_config.self_port, autoconn_custodian)
      end

      // let notify = _ServerListener.create(logger, self_pk, self_sk, custodian)
      // TCPListener(NetAuth(auth), consume notify, self_config.self_ip, self_config.self_port)

      _RegisterHandler.apply(custodian)
    else
      logger(Error) and logger.log("Couldn't start server")
    end

// class _ServerListener is TCPListenNotify
//   let _log: Logger[String val]
//   let _pk: Ed25519Public
//   let _sk: Ed25519Secret
//   let _custodian: Custodian

//   new iso create(
//     logger: Logger[String val],
//     pk: Ed25519Public,
//     sk: Ed25519Secret,
//     custodian: Custodian)
// =>
//     _log = logger
//     (_pk, _sk) = (pk, sk)
//     _custodian = custodian

//   fun ref listening(listen: TCPListener ref) =>
//     try
//       (let addr, let port) = listen.local_address().name()?
//       _log(Info) and _log.log("Server listening on " + addr + ":" + port)
//     else
//       _log(Error) and _log.log("Couldn't get local address")
//       listen.close()
//     end

//   fun ref connected(listen: TCPListener): TCPConnectionNotify iso^ =>
//     _log(Info) and _log.log("Server starting with SHS")
//     _SHSNotify.server(_pk, _sk, _custodian, HandshakeServer(_pk, _sk, DefaultNetworkId()))

//   fun ref not_listening(listen: TCPListener ref) =>
//     _log(Error) and _log.log("Server not listening")
//     listen.close()

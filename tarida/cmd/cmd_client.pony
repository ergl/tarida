use "../config"
use "../discovery"
use "../sodium"
use "../identity"

use "bureaucracy"
use "logger"
use "net"
use "signals"

class CmdClient is CmdType
  fun ref apply(
    logger: Logger[String val],
    auth: AmbientAuth,
    config: Config)
  =>

    try
      let self_config = config.mode_config as ClientConfig

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

      let server_pk_bytes = Identity.decode_cypherlink(self_config.server_pk)?
      let server_pk = Sodium.ed25519_pk_from_bytes(server_pk_bytes)?

      // custodian(Handshake.client(auth, public, secret, server_pk,
      //   self_config.self_ip, self_config.self_port))

      // _RegisterHandler.apply(custodian)
    else
      logger(Error) and logger.log("Couldn't start server")
    end


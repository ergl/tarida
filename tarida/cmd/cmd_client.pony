use "../config"
use "../announcements"
use "../sodium"
use "../identity"
use "../handlers"
use "../shs"
use "../boxstream"

use "bureaucracy"
use "files"
use "logger"
use "net"
use "signals"

class CmdClient
  fun ref apply(
    logger: Logger[String val],
    auth: AmbientAuth,
    config: Config,
    self_config: ClientConfig)
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
        // Discovery(auth, public, secret, self_config.self_ip, "8008",
        //   self_config.self_port, autoconn_custodian)
      end

      logger(Info) and logger.log("About to decode: " + self_config.server_pk)
      let server_pk_bytes = Identity.decode_cypherlink(self_config.server_pk)?
      logger(Info) and logger.log("Was able to decode cypherlink")
      let server_pk = Sodium.ed25519_pk_from_bytes(server_pk_bytes)?

      logger(Info) and logger.log("Got server public key")

      let conn = TCPConnection(
        NetAuth(auth),
        BoxStreamConnection.client(
          logger,
          RPCNotify(RPCConnectionServer(
            logger,
            public,
            secret
          )),
          public,
          secret,
          server_pk,
          DefaultNetworkId()
        ),
        self_config.server_ip,
        self_config.server_port,
        self_config.self_ip
      )

      custodian(conn)

      _RegisterHandler.apply(custodian)
    else
      logger(Error) and logger.log("Couldn't start client")
    end


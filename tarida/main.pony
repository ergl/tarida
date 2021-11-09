use "debug"
use "logger"
use "signals"
use "bureaucracy"
use net = "net"

use "shs"
use "sodium"

class QuitConnections is SignalNotify
  let _c: Custodian

  new iso create(c: Custodian) => _c = c

  fun ref apply(count: U32): Bool =>
    _c.dispose()
    true

actor Main
  new create(env: Env) =>
    try
      // TODO(borja): Read identity from config.config_path
      let auth = env.root as AmbientAuth
      (let public, let secret) = Identity.generate()?

      let config = ArgConfig(env)?
      let logger = StringLogger(config.log_level, env.out)

      let connection_custodian = Custodian
        let autoconn_custodian =
          if config.enable_autoconnect then
            connection_custodian
          else
            None
          end

      match config.mode_config
      | let i: InviteConfig =>
        // TODO(borja): This should be stored somewhere so that we know it can be redeemed
        // TODO(borja): Convert this into a command that can be sent to the server
        (let inv_pub, let inv_priv) = Identity.generate()?
        let invite = Identity.encode_invite(i.self_ip, i.self_port,
          public, Sodium.ed25519_pair_sk_to_seed(inv_priv)?)
        env.out.print(
          "Invite generated: " + consume invite + "\n\n"
          + "Share the code below with anyone you want:\n"
          + Identity.cypherlink(inv_pub))
        return

      | let s: ServerConfig =>
        if config.enable_discovery then
          Discovery(auth, public, secret, s.self_ip, "8008", s.self_port, autoconn_custodian)
        end
        _enable_server_mode(auth, logger, public, secret, s, connection_custodian)

      | let c: ClientConfig =>
        if config.enable_discovery then
          Discovery(auth, public, secret, c.self_ip, "8008", c.self_port, autoconn_custodian)
        end
        _enable_client_mode(auth, public, secret, c, connection_custodian)?

      end

      // Quit all connections when the user quits
      SignalHandler(QuitConnections(connection_custodian), Sig.term())
    end

  fun _enable_server_mode(
    auth: AmbientAuth,
    logger: Logger[String val],
    self_pk: Ed25519Public,
    self_sk: Ed25519Secret,
    config: ServerConfig,
    custodian: Custodian)
  =>
    let notify = Listener.create(logger, self_pk, self_sk, custodian)
    net.TCPListener(net.NetAuth(auth), consume notify, config.self_ip, config.self_port)

  fun _enable_client_mode(
    auth: AmbientAuth,
    self_pk: Ed25519Public,
    self_sk: Ed25519Secret,
    config: ClientConfig,
    custodian: Custodian)
    ?
  =>
    let other_pk_bytes = Identity.decode_cypherlink(config.server_pk)?
    let other_pk = Sodium.ed25519_pk_from_bytes(other_pk_bytes)?

    custodian(Handshake.client(auth, self_pk, self_sk, other_pk, config.self_ip, config.self_port))

class Listener is net.TCPListenNotify
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

  fun ref listening(listen: net.TCPListener ref) =>
    try
      (let addr, let port) = listen.local_address().name()?
      _log(Info) and _log.log("Server listening on " + addr + ":" + port)
    else
      _log(Error) and _log.log("Couldn't get local address")
      listen.close()
    end

  fun ref connected(listen: net.TCPListener): net.TCPConnectionNotify iso^ =>
    _log(Info) and _log.log("Server starting with SHS")
    _SHSNotify.server(_pk, _sk, _custodian, HandshakeServer(_pk, _sk, DefaultNetworkId()))

  fun ref not_listening(listen: net.TCPListener ref) =>
    _log(Error) and _log.log("Server not listening")
    listen.close()

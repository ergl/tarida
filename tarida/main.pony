use "debug"
use "logger"
use "signals"
use "bureaucracy"

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
        Handshake.server(auth, public, secret, s.self_port, connection_custodian)

      | let c: ClientConfig =>
        if config.enable_discovery then
          Discovery(auth, public, secret, c.self_ip, "8008", c.self_port, autoconn_custodian)
        end
        _enable_client_mode(auth, public, secret, c, connection_custodian)?

      end

      // Quit all connections when the user quits
      SignalHandler(QuitConnections(connection_custodian), Sig.term())
    end

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

use "sodium"
use "net"
use "debug"

actor Main
  fun tag _enable_discovery(
    auth: NetAuth,
    self_pk: Ed25519Public,
    addr: String,
    peer_port: String)
  =>
    let port = "8008"
    let encoded_id = Identity.encode(self_pk)
    Discovery(auth, consume encoded_id, addr, port, peer_port)

  fun tag _enable_server_mode(
    auth: NetAuth,
    self_pk: Ed25519Public,
    self_sk: Ed25519Secret,
    peering_port: String,
    config: ServerConfig)?
  =>
    if config.is_pub then
      // TODO(borja): This should be stored somewhere
      (let inv_pub, let inv_priv) = Identity.generate()?
      let seed = Sodium.ed25519_pair_sk_to_seed(inv_priv)?
      let invite = Identity.encode_invite(
        config.pub_domain,
        config.pub_port,
        self_pk,
        seed
      )

      // TODO(borja): Add command to create this on demand
      Debug.out("Pub invite: " + consume invite)
      Debug.out("Invites should supply: " + Identity.cypherlink(inv_pub))
    end

    PeerServer(auth, self_pk, self_sk, peering_port)

  fun _enable_client_mode(
    auth: NetAuth,
    self_pk: Ed25519Public,
    self_sk: Ed25519Secret,
    config: ClientConfig)?
  =>
    error

  new create(env: Env) =>
    try
      // TODO(borja): Read identity from config.config_path
      Sodium.init()?
      let auth = NetAuth(env.root as AmbientAuth)
      (let public, let secret) = Identity.generate()?

      let config = ArgConfig(env)?
      let peer_port = config.peering_port
      if config.enable_discovery then
        _enable_discovery(auth, public, config.local_broadcast_ip, peer_port)
      end

      match config.mode_config
      | let s: ServerConfig => _enable_server_mode(auth, public, secret, peer_port, s)?
      | let c: ClientConfig => _enable_client_mode(auth, public, secret, c)?
      end
    end

use "sodium"
use "net"

actor Main
  new create(env: Env) =>
    try
      // TODO(borja): Read identity from config.config_path
      Sodium.init()?
      let auth = env.root as AmbientAuth
      (let public, let secret) = Identity.generate()?

      let config = ArgConfig(env)?
      let peer_port = config.peer_port
      if config.local_broadcast then
        // TODO(borja): Find a way to get the IP,
        // we need it for the advert
        let iface = "en0"
        let broadcast_port = "8008"
        // TODO(borja): Consider using bureaucracy.Registrar for services
        Discovery(
          auth,
          Identity.encode(public),
          iface,
          broadcast_port,
          peer_port
        )
      end

      PeerServer(NetAuth(auth), public, secret, peer_port)
    end

use "sodium"
use "net"

actor Main
  new create(env: Env) =>
    try
      Sodium.init()?
      let auth = env.root as AmbientAuth
      // TODO(borja): Find a way to get the IP,
      // we need it for the advert
      let iface = "en0"
      let peer_port = "9999"
      let broadcast_port = "8008"

      // TODO(borja): Consider using bureaucracy.Registrar for services
      (let public, let secret) = Identity.generate()?
      Discovery(auth, Identity.encode(public), iface, broadcast_port, peer_port)
      PeerServer(NetAuth(auth), public, secret, peer_port)
    end

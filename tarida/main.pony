use "sodium"
use "net"

actor Main
  new create(env: Env) =>
    try
      Sodium.init()?
      let auth = env.root as AmbientAuth

      (let public, let secret) = Identity.generate()?
      Discovery(auth, "en0", "8008", Identity.encode(public))
    end

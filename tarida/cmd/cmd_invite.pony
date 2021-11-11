use "../config"
use "../sodium"
use "../identity"

use "files"
use "logger"

class CmdInvite
  fun ref apply(
    logger: Logger[String val],
    auth: AmbientAuth,
    config: Config,
    self_config: InviteConfig)
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

      // TODO(borja): This should be stored somewhere so that we know it can be redeemed
      // TODO(borja): Convert this into a command that can be sent to the server
      (let inv_pub, let inv_priv) = Identity.generate()?
      let invite = Identity.encode_invite(self_config.self_ip, self_config.self_port,
        public, Sodium.ed25519_pair_sk_to_seed(inv_priv)?)
      logger(Info) and logger.log(
        "Invite generated: " + consume invite + "\n\n"
            + "Share the code below with anyone you want:\n"
            + Identity.cypherlink(inv_pub)
      )
    end

use "../config"
use "../sodium"
use "../identity"

use "logger"

class CmdInvite is CmdType
  fun ref apply(
    logger: Logger[String val],
    auth: AmbientAuth,
    config: Config)
  =>
    try
      let self_config = config.mode_config as InviteConfig

      // TODO(borja): Read identity from config.config_path
        (let public, let secret) = Identity.generate()?

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

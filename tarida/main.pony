use "config"
use "cmd"

use "logger"

actor Main
  new create(env: Env) =>
    try
      let auth = env.root as AmbientAuth

      let config = ParseArgs(env)?
      let logger = StringLogger(config.log_level, env.out)

      match config.mode_config
      | let invite: InviteConfig =>
        CmdInvite(logger, auth, config, invite)
      | let identity: GenIdentityConfig =>
        CmdIdentity(logger, auth, config, identity)
      | let server: ServerConfig =>
        CmdServer(logger, auth, config, server)
      | let client: ClientConfig =>
        CmdClient(logger, auth, config, client)
      end
    end

use "config"
use "cmd"

use "logger"

actor Main
  new create(env: Env) =>
    try
      // TODO(borja): Read identity from config.config_path
      let auth = env.root as AmbientAuth

      let config = ParseArgs(env)?
      let logger = StringLogger(config.log_level, env.out)

      match config.mode_config
      | let i: InviteConfig =>
        CmdInvite(logger, auth, config)
      // | let id: GenIdentityConfig =>
      //   CmdGenIdentity(logger, auth, config)
      | let server: ServerConfig =>
        CmdServer(logger, auth, config)
      | let client: ClientConfig =>
        CmdClient(logger, auth, config)
      else
        logger(Error) and logger.log("Mode not supported")
        error
      end
    end

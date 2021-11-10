use "../config"

use "logger"

trait CmdType
  fun ref apply(
    logger: Logger[String val],
    auth: AmbientAuth,
    config: Config)
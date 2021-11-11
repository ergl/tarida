use "cli"
use logger = "logger"

class val InviteConfig
  var self_ip: String = ""
  var self_port: String = ""

class val GenIdentityConfig

class val ServerConfig
  var self_ip: String = ""
  var self_port: String = ""

class val ClientConfig
  var server_pk: String = ""
  var server_ip: String = ""
  var server_port: String = ""
  var self_ip: String = ""
  var self_port: String = ""

class val Config
  var log_level: logger.LogLevel = logger.Error
  var identity_path: String = ""
  var enable_discovery: Bool = false
  var enable_autoconnect: Bool = false
  var mode_config: (ServerConfig
    | ClientConfig
    | InviteConfig
    | GenIdentityConfig) = ServerConfig

primitive ParseArgs
  fun apply(env: Env): Config? =>
    let cmd = _parse(env)?
    let config = Config

    config.log_level =
      match cmd.option("log").u64()
      | 0 => logger.Error
      | 1 => logger.Warn
      | 2 => logger.Info
      else
        logger.Fine
      end

    config.identity_path = cmd.option("identity").string()
    if config.identity_path.size() == 0 then
      env.err.print("Error: empty identity path")
      env.exitcode(1)
      error
    end

    config.enable_discovery = cmd.option("broadcast").bool()
    config.enable_autoconnect = cmd.option("autoconnect").bool()

    config.mode_config =
      match cmd.fullname()
      | "tarida/client" => _parse_client_config(env, cmd)?
      | "tarida/server" => _parse_server_config(env, cmd)
      | "tarida/gen_invite" => _parse_geninvite_config(env, cmd)
      | "tarida/gen_identity" => GenIdentityConfig
      else
        // Can't happen, since _parse will do it for us, but you never know
        env.err.print("Error: bad command " + cmd.fullname())
        env.exitcode(1)
        error
      end

    config

  fun _parse_client_config(
    env: Env,
    cmd: Command)
    : ClientConfig val
    ?
  =>
    let client_config = ClientConfig
    client_config.server_pk = cmd.option("server_pk").string()
    client_config.server_ip = cmd.option("server_ip").string()
    client_config.server_port = cmd.option("server_port").string()
    client_config.self_ip = cmd.option("self_ip").string()
    client_config.self_port = cmd.option("self_port").string()

    if client_config.server_pk.size() == 0 then
      env.err.print("Error: need the public key of the server")
      env.exitcode(1)
      error
    end

    client_config

  fun _parse_server_config(
    env: Env,
    cmd: Command)
    : ServerConfig val
  =>
    let server_config = ServerConfig
    server_config.self_ip = cmd.option("ip").string()
    server_config.self_port = cmd.option("port").string()
    server_config

  fun _parse_geninvite_config(
    env: Env,
    cmd: Command)
    : InviteConfig val
  =>
    let invite_config = InviteConfig
    invite_config.self_ip = cmd.option("ip").string()
    invite_config.self_port = cmd.option("port").string()
    invite_config

  fun _parse(env: Env): Command? =>
    let spec = _spec()?
    match CommandParser(spec).parse(env.args)
    | let c: Command => c

    | let c: CommandHelp =>
      c.print_help(env.out)
      env.exitcode(0)
      error

    | let err: SyntaxError =>
      env.err.print(err.string())
      let help = Help.general(spec)
      help.print_help(env.err)
      env.exitcode(1)
      error
    end

  fun _spec(): CommandSpec? =>
    CommandSpec.parent(
      "tarida",
      "A work-in-progress SSB implementation",
      [
        OptionSpec.u64(
          "log",
          "Configure log output: 0=err, 1=warn, 2=info, 3=fine."
          where short' = 'g',
          default' = 0)

        OptionSpec.string(
          "identity",
          "Path to identity file"
          where short' = 'i')

        OptionSpec.bool(
          "broadcast",
          "Enable local UDP broadcast"
          where short' = 'b',
          default' = false)

        OptionSpec.bool(
          "broadcast_autoconnect",
          "Attempt to utoconnect to received local announcements"
          where default' = false)
      ],
      [
        _server_command()?
        _client_command()?
        _gen_invite_command()?
        _gen_identity_command()?
      ]
    )?
    .>add_help()?

  fun _server_command(): CommandSpec? =>
    CommandSpec.leaf(
      "server",
      "start tarida in server mode",
      [
        OptionSpec.string(
          "ip",
          "The IP address of this server"
          where default' = "")

        OptionSpec.string(
          "port",
          "The port of this server"
          where default' = "9999")
      ],
      []
    )?
    .>add_help()?

  fun _client_command(): CommandSpec? =>
    CommandSpec.leaf(
      "client",
      "start tarida in client mode",
      [
        OptionSpec.string(
          "server_pk",
          "The server's public key")

        OptionSpec.string(
          "server_ip",
          "Server IP address"
          where default' = "")

        OptionSpec.string(
          "server_port",
          "Server port"
          where default' = "9999")

        OptionSpec.string(
          "self_ip",
          "Client IP address"
          where default' = "")

        OptionSpec.string(
          "self_port",
          "Client port"
          where default' = "9999")
      ]
    )?
    .>add_help()?

  fun _gen_invite_command(): CommandSpec? =>
    CommandSpec.leaf(
      "gen_invite",
      "generate a pub invitation",
      [
        OptionSpec.string(
          "ip",
          "The IP address of this server"
          where default' = "")

        OptionSpec.string(
          "port",
          "The port of this server"
          where default' = "9999")
      ]
    )?
    .>add_help()?

  fun _gen_identity_command(): CommandSpec? =>
    CommandSpec
      .leaf("gen_identity", "generate a stable identity")?
      .>add_help()?

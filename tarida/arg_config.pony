use "cli"

class val TaridaConfig
  var local_broadcast: Bool = true
  var is_pub: Bool = false
  var config_path: String = ""
  var peer_port: String = "9999"

primitive ArgConfig
  fun _spec(): CommandSpec? =>
    CommandSpec.leaf(
      "tarida",
      "WIP SSB server",
      [
        OptionSpec.bool(
          "broadcast",
          "Tells tarida to broadcast to peers locally"
          where short' = 'b', default' = false
        )

        OptionSpec.bool(
          "pub",
          "Tells tarida to act as a pub (generate invites)"
          where short' = 'p', default' = false
        )

        OptionSpec.string(
          "id_path",
          "Tells tarida where to find the configuration file"
          where short' = 'f', default' = ""
        )

        OptionSpec.string(
          "peer_port",
          "Peer TCP port"
          where short' = 't', default' = "9999"
        )
      ]
    )?.>add_help()?

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

  fun apply(env: Env): TaridaConfig? =>
    let cmd = _parse(env)?
    let config = TaridaConfig

    config.local_broadcast = cmd.option("broadcast").bool()
    config.is_pub = cmd.option("pub").bool()
    config.config_path = cmd.option("id_path").string()
    config.peer_port = cmd.option("peer_port").string()
    config

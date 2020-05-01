use "cli"

class val ServerConfig
  var is_pub: Bool = false
  var pub_domain: String = ""
  var pub_port: String = ""

class val ClientConfig
  var target_pk: String = ""
  var target_ip: String = ""
  var target_port: String = ""

class val TaridaConfig
  var config_path: String = ""
  var enable_discovery: Bool = false
  var enable_autoconnect: Bool = false
  var peering_port: String = "9999"
  var local_broadcast_ip: String = ""
  var mode_config : (ServerConfig | ClientConfig) = ServerConfig

primitive ArgConfig
  fun _client_spec(): CommandSpec? =>
    CommandSpec.leaf(
      "client",
      "start tarida in client mode",
      [ OptionSpec.string("target_pk", "The peer public key")
        OptionSpec.string("target_ip", "The peer IP address")
        OptionSpec.string("target_port", "The peer port") ]
    )?.>add_help()?

  fun _server_spec(): CommandSpec? =>
    CommandSpec.leaf(
      "server",
      "start tarida in server mode",
      [ OptionSpec.bool(
        "pub",
        "Turn this server into a pub"
        where short' = 'p', default' = false) ],
      [ ArgSpec.string("pub_domain", "Public pub domain", "")
        ArgSpec.string("pub_port", "Public pub port", "") ]
    )?.>add_help()?

  fun _spec(): CommandSpec? =>
    CommandSpec.parent(
      "tarida",
      "WIP SSB implementation",
      [ OptionSpec.string("broadcast",
                          "Tells tarida the IP used to broadcast to peers locally",
                          'b')

        OptionSpec.bool("autoconnect",
                        "Autoconnect to local announcements"
                        where default' = false)

        OptionSpec.string("id_path",
                          "Tells tarida where to find the configuration file",
                          'f')

        OptionSpec.string("peer_port", "Peering TCP port"
                          where short' = 't', default' = "9999") ],
      [ _server_spec()?; _client_spec()? ]
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

  fun _fill_client_config(env: Env, config: TaridaConfig iso, cmd: Command): TaridaConfig? =>
    let client_config = ClientConfig
    let target_pk = cmd.option("target_pk").string()
    let target_ip = cmd.option("target_ip").string()
    let target_port = cmd.option("target_port").string()

    if (target_pk.size() == 0) or (target_port.size() == 0) then
      env.err.print("Error: no real data supplied")
      env.exitcode(1)
      error
    end

    client_config.target_pk = target_pk
    client_config.target_ip = target_ip
    client_config.target_port = target_port
    config.mode_config = consume client_config
    config

  fun _fill_server_config(env: Env, config: TaridaConfig iso, cmd: Command): TaridaConfig? =>
    let server_config = ServerConfig
    server_config.is_pub = cmd.option("pub").bool()
    if server_config.is_pub then
      let pub_domain = cmd.arg("pub_domain").string()
      let pub_port = cmd.arg("pub_port").string()
      if (pub_domain.size() == 0) or (pub_port.size() == 0) then
        env.err.print("Error: server is pub, but no domain or port was given")
        env.exitcode(1)
        error
      end

      server_config.pub_domain = pub_domain
      server_config.pub_port = pub_port
    end

    config.mode_config = consume server_config
    config

  fun apply(env: Env): TaridaConfig? =>
    let cmd = _parse(env)?
    let config = TaridaConfig

    config.config_path = cmd.option("id_path").string()
    config.local_broadcast_ip = cmd.option("broadcast").string()
    // FIXME(borja): Default values are being ignored
    let got_peering_port = cmd.option("peer_port").string()
    if got_peering_port.size() != 0 then
      config.peering_port = got_peering_port
    end

    config.enable_discovery = (config.local_broadcast_ip != "")
    config.enable_autoconnect = cmd.option("autoconnect").bool()
    match cmd.fullname()
    | "tarida/client" => _fill_client_config(env, consume config, cmd)?
    | "tarida/server" => _fill_server_config(env, consume config, cmd)?
    else
      // Can't happen, since _parse will do it for us, but you never know
      env.err.print("Error: bad command " + cmd.fullname())
      env.exitcode(1)
      error
    end

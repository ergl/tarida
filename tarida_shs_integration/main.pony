use "cli"
use "term"
use "promises"
use "encode/base64"
use "package:../tarida/shs"
use "package:../tarida/sodium"

primitive Client
primitive Server
type Mode is (Client | Server)
class val IntConfig
  var mode: Mode = Client
  var seed: String = ""

primitive Config
  fun _spec(): CommandSpec? =>
    CommandSpec.leaf(
      "shs-test",
      "Integration tests for SSB SHS",
      [
        OptionSpec.bool(
          "client",
          "Act as a client",
          'c',
          true
        )
        OptionSpec.bool(
          "server",
          "Act as a server",
          's',
          false
        )
        OptionSpec.string(
          "seed",
          "Seed to generate identities and ephemeral keys",
          'd'
        )
      ]
    )?.>add_help()?

  fun _parse(env: Env): Command? =>
    let spec = _spec()?
    match CommandParser(spec).parse(env.args)
    | let c: Command => c
    | let  c: CommandHelp =>
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

  fun apply(env: Env): IntConfig? =>
    let cmd = _parse(env)?
    let config = IntConfig

    let client = cmd.option("client").bool()
    let server = cmd.option("server").bool()

    config.mode = if server == true then Server else Client end
    config.seed = cmd.option("seed").string()
    config

actor Main
  new create(env: Env) =>
    try
      Sodium.init()?
      let config = Config(env)?
      let seed = String.from_array(recover val Array[U8].init(0, 32) end)
      let notify = match config.mode
      | Client => Input.client(env, seed)
      | Server => Input.server(env, seed)
      end
      env.input(consume notify)
    end

primitive Input
  fun client(env: Env, seed: String): InputNotify iso^ =>
    let act = ClientInput(env.out, seed)
    let term = _make_ansiterm(env, ForwardNotify(act))
    env.out.print("Testing client")
    act.ready(term)
    _to_notify(term)

  fun server(env: Env, seed: String): InputNotify iso^ =>
    let act = ServerInput(env.out, seed)
    let term = _make_ansiterm(env, ForwardNotify(act))
    env.out.print("Testing server")
    act.ready(term)
    _to_notify(term)

  fun _make_ansiterm(env: Env, notify: ReadlineNotify iso): ANSITerm =>
    ANSITerm(Readline(consume notify, env.out), env.input)

  fun _to_notify(term: ANSITerm): InputNotify iso^ =>
    object iso
      let term: ANSITerm = term
      fun ref apply(data: Array[U8] iso) => term(consume data)
      fun ref dispose() => term.dispose()
    end

interface tag InputActor
  be ready(term: ANSITerm)
  be apply(line: String, prompt: Promise[String])

class iso ForwardNotify is ReadlineNotify
  let _dst: InputActor
  fun ref tab(line: String val): Seq[String val] box => []
  fun ref apply(line: String, prompt: Promise[String]) => _dst.apply(line, prompt)
  new iso create(dst: InputActor) =>
    _dst = dst

actor ServerInput is InputActor
  let _out: OutStream
  let _seed: String

  var _term: (ANSITerm|None) = None

  var _public: (Ed25519Public|None) = None
  var _secret: (Ed25519Secret|None) = None

  var _server_fsm: (HandshakeServer|None) = None

  new create(out: OutStream, seed: String) =>
    _out = out
    _seed = seed

  be ready(term: ANSITerm) =>
    _term = term
    term.prompt("Input client_hello: ")
    _do_init()

  be apply(line: String, prompt: Promise[String]) =>
    try
      (let expect, let resp) = (_server_fsm as HandshakeServer).step(String.from_array(Base64.decode(line)?))?
      _out.print(Base64.encode(resp))
      prompt("Next message> ")
    else
      prompt.reject()
    end

  fun ref _do_init() =>
    try
      (let self_pk, let self_sk) = Sodium.ed25519_pair_seed(_seed)?
      _server_fsm = HandshakeServer.create(
        self_pk,
        self_sk
      )
      (_server_fsm as HandshakeServer).init()?
    end

actor ClientInput is InputActor
  let _out: OutStream
  let _seed: String

  var _term: (ANSITerm|None) = None

  var _public: (Ed25519Public|None) = None
  var _secret: (Ed25519Secret|None) = None
  var _other_public: (Ed25519Public|None) = None

  var _client_fsm: (HandshakeClient|None) = None

  new create(out: OutStream, seed: String) =>
    _out = out
    _seed = seed

  be ready(term: ANSITerm) =>
    _term = term
    term.prompt("Press enter to continue: ")
    _do_init()

  be apply(line: String, prompt: Promise[String]) =>
    try
      (let expect, let resp) = (_client_fsm as HandshakeClient).step(String.from_array(Base64.decode(line)?))?
      _out.print(Base64.encode(resp))
      prompt("Next message> ")
    else
      prompt.reject()
    end

  fun ref _do_init() =>
    try
      (let self_pk, let self_sk) = Sodium.ed25519_pair_seed(_seed)?
      (_public, _secret) = (self_pk, self_sk)
      (let other_pk, _) = Sodium.ed25519_pair_seed(_seed)?
      _other_public = other_pk
      _client_fsm = HandshakeClient.create(
        self_pk,
        self_sk,
        other_pk
      )
    end

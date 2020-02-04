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

    config.mode = if client == true then Client else Server end
    config.seed = cmd.option("seed").string()
    config

actor Main
  new create(env: Env) =>
    try
      let config = Config(env)?
      let notify = match config.mode
      | Client => Input.client(env, config.seed)
      | Server => Input.server(env, config.seed)
      end
      env.input(consume notify)
    end

primitive Input
  fun client(env: Env, seed: String): InputNotify iso^ =>
    let term = _make_ansiterm(env, recover ClientNotify(env.out, seed) end)
    env.out.print("Testing client")
    term.prompt("Input server_hello: ")
    _to_notify(term)

  fun server(env: Env, seed: String): InputNotify iso^ =>
    let term = _make_ansiterm(env, recover ServerNotify(env.out, seed) end)
    env.out.print("Testing server")
    term.prompt("Input client_hello: ")
    _to_notify(term)

  fun _make_ansiterm(env: Env, notify: ReadlineNotify iso): ANSITerm =>
    ANSITerm(Readline(consume notify, env.out), env.input)

  fun _to_notify(term: ANSITerm): InputNotify iso^ =>
    object iso
      let term: ANSITerm = term
      fun ref apply(data: Array[U8] iso) => term(consume data)
      fun ref dispose() => term.dispose()
    end

class ServerNotify is ReadlineNotify
  let _out: OutStream
  let _seed: String

  fun ref tab(line: String val): Seq[String val] box => []
  new create(out: OutStream, seed: String) =>
    _out = out
    _seed = seed

  fun ref apply(line: String, prompt: Promise[String] tag) =>
    prompt("Hey :^)")

class ClientNotify is ReadlineNotify
  let _out: OutStream
  let _seed: String

  var _public: (Ed25519Public|None) = None
  var _secret: (Ed25519Secret|None) = None
  var _other_public: (Ed25519Public|None) = None

  var _client_fsm: (HandshakeClient|None) = None

  fun ref tab(line: String val): Seq[String val] box => []
  new create(out: OutStream, seed: String) =>
    _out = out
    _seed = seed
    _do_init()

  fun ref apply(line: String, prompt: Promise[String] tag) =>
    try
      (let expect, let resp) = (_client_fsm as HandshakeClient).step(line)?
      _out.print(Base64.encode(resp))
      prompt("Next message> ")
    else
      prompt.reject()
    end

  fun ref _do_init() =>
    try
      (let self_pk, let self_sk) = Sodium.ed25519_pair()?
      (_public, _secret) = (self_pk, self_sk)
      (let other_pk, _) = Sodium.ed25519_pair()?
      _other_public = other_pk
      _client_fsm = HandshakeClient.create(
        self_pk,
        self_sk,
        other_pk
      )
    end
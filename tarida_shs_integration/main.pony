// Follow from https://github.com/AljoschaMeyer/shs1-test
// Convert from Readline into normal input/output, with expect

use "cli"
use "term"
use "format"
use "promises"
use "package:../tarida/shs"
use "package:../tarida/sodium"

class val ClientConfig
  let netid: String
  let server_id_pk: Ed25519Public

  new val create(netid': String, pk': Ed25519Public) =>
    netid = netid'
    server_id_pk = pk'

class val ServerConfig
  let netid: String
  let server_id_pk: Ed25519Public
  let server_id_sk: Ed25519Secret

  new val create(netid': String, server_id_pk': Ed25519Public, server_id_sk': Ed25519Secret) =>
    netid = netid'
    server_id_pk = server_id_pk'
    server_id_sk = server_id_sk'

primitive Config
  fun apply(env: Env): (ClientConfig | ServerConfig)? =>
    let args = env.args
    if args.size() == 3 then
      let netid = String.from_array(Hex.decode(args(1)?)?)
      let server_pk = Hex.decode(args(2)?)?
      ClientConfig(netid, Ed25519Public(consume server_pk))
    elseif args.size() == 4 then
      let netid = String.from_array(Hex.decode(args(1)?)?)
      let server_pk = Hex.decode(args(2)?)?
      let server_sk = Hex.decode(args(3)?)?
      ServerConfig(netid, Ed25519Public(consume server_pk), Ed25519Secret(consume server_sk))
    else
      error
    end

primitive Hex
  // From https://stackoverflow.com/a/35452093
  fun decode(s: String): Array[U8] iso^? =>
    let size = s.size()
    if (size and 0x01) != 0 then error end
    let arr = recover Array[U8].create(size >> 1) end

    var j: USize = 0
    while j < size do
      let c = s(j)?
      let value = if (c >= '0') and (c <= '9') then
        (c - '0')
      elseif (c >= 'A') and (c <= 'F') then
        10 + (c - 'A')
      elseif (c >= 'a') and (c <= 'f') then
         10 + (c - 'a')
      else
        error
      end

      arr.push(value << (((j + 1) % 2) * 4).u8())
      j = j + 2
    end
    consume arr

  fun encode(arr: Array[U8] box): String =>
    let s = recover String.create(arr.size() * 2) end
    for v in arr.values() do
      s.append(Format.int[U8](v where fmt = FormatHexBare, width=2, fill='0'))
    end
    s

actor Main
  new create(env: Env) =>
    try
      Sodium.init()?
      let config = Config(env)?
      let notify = match config
      | let c: ClientConfig =>
        (let pk, let sk) = Sodium.ed25519_pair()?
        Input.client(env, c, pk, sk)
      | let c: ServerConfig => Input.server(env, c)
      end
      env.input(consume notify)
    end

primitive Input
  fun client(env: Env, c: ClientConfig, pk: Ed25519Public, sk: Ed25519Secret): InputNotify iso^ =>
    let act = ClientInput(env.out, c.netid, pk, sk, c.server_id_pk)
    let term = _make_ansiterm(env, ForwardNotify(act))
    act.ready(term)
    _to_notify(term)

  fun server(env: Env, c: ServerConfig): InputNotify iso^ =>
    let act = ServerInput(env.out, c.netid, c.server_id_pk, c.server_id_sk)
    let term = _make_ansiterm(env, ForwardNotify(act))
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
  var _term: (ANSITerm|None) = None

  let _netid: String
  let _public: Ed25519Public
  let _secret: Ed25519Secret
  let _server_fsm: HandshakeServer

  new create(out: OutStream, netid: String, public: Ed25519Public, secret: Ed25519Secret) =>
    _out = out
    _netid = netid
    _public = public
    _secret = secret
    _server_fsm = HandshakeServer.create(_public,_secret)
    try _server_fsm.init()? end

  be ready(term: ANSITerm) =>
    _term = term
    term.prompt("")

  be apply(line: String, prompt: Promise[String]) =>
    try
      (let _, let resp) = _server_fsm.step(String.from_array(Hex.decode(line)?))?
      _out.print(resp)
      prompt("")
    else
      prompt.reject()
    end

actor ClientInput is InputActor
  let _out: OutStream
  var _term: (ANSITerm|None) = None

  let _netid: String
  let _public: Ed25519Public
  let _secret: Ed25519Secret
  let _other_public: Ed25519Public
  let _client_fsm: HandshakeClient

  new create(out: OutStream,
             netid: String,
             public: Ed25519Public,
             secret: Ed25519Secret,
             other: Ed25519Public) =>

    _out = out
    _netid = netid
    _public = public
    _secret = secret
    _other_public = other
    _client_fsm = HandshakeClient(_public, _secret, _other_public)

  be ready(term: ANSITerm) =>
    _term = term
    term.prompt("")

  be apply(line: String, prompt: Promise[String]) =>
    try
      (let _, let resp) = _client_fsm.step(String.from_array(Hex.decode(line)?))?
      _out.print(resp)
      prompt("")
    else
      prompt.reject()
    end

use "debug"
use "cli"
use "signals"
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
      let server_sk = Hex.decode(args(2)?)?
      let server_pk = Hex.decode(args(3)?)?
      ServerConfig(netid, Ed25519Public(consume server_pk), Ed25519Secret(consume server_sk))
    else
      error
    end

class SigTermHandler is SignalNotify
  let _input: InputStream
  new iso create(input: InputStream) => _input = input
  fun ref apply(count: U32): Bool =>
    _input.dispose()
    false

type Exit is {(I32)} val

actor Main
  new create(env: Env) =>
    try
      let config = Config(env)?
      let signal = SignalHandler(SigTermHandler(env.input), Sig.term())
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
    Buffer(env.input, ClientInput(env.out, env.exitcode, c.netid, pk, sk, c.server_id_pk), 64)

  fun server(env: Env, c: ServerConfig): InputNotify iso^ =>
    Buffer(env.input, ServerInput(env.out, env.exitcode, c.netid, c.server_id_pk, c.server_id_sk))

class iso ServerInput is BufferedInputNotify
  let _out: OutStream
  let _set_exit: Exit

  let _netid: Array[U8] val
  let _public: Ed25519Public
  let _secret: Ed25519Secret
  var _server_fsm: HandshakeServer

  new iso create(out: OutStream, exitcode: Exit, netid: String, public: Ed25519Public, secret: Ed25519Secret) =>
    _out = out
    _set_exit = exitcode

    _public = public
    _secret = secret
    _netid = netid.array()
    _server_fsm = HandshakeServer.create(_public, _secret, _netid)
    try _server_fsm.init()? else Debug.err("bad server init") end

  fun ref apply(parent: BufferedInput ref, data: Array[U8] iso): Bool =>
    let maybe_response = try
      _server_fsm.step(String.from_iso_array(consume data))?
    else
      None
    end

    match maybe_response
    | None =>
      _set_exit(1)
      false

    | (let expect: USize, let response: String) =>
      _out.write(response)
      _out.flush()
      if expect != 0 then
        try parent.expect(expect)? else Debug.err("error while expecting") end
        true
      else
        let server = _server_fsm = HandshakeServer(_public, _secret, _netid)
        let maybe_keys = try server.boxstream()?.keys() else Debug.err("boxkeys error"); None end
        match maybe_keys
        | let keys: Array[U8] val => _out.write(keys)
        else None end
        false
      end
    end

class iso ClientInput is BufferedInputNotify
  let _out: OutStream
  let _set_exit: Exit

  let _public: Ed25519Public
  let _secret: Ed25519Secret
  let _other_public: Ed25519Public
  let _netid: Array[U8] val
  var _client_fsm: HandshakeClient

  new iso create(
    out: OutStream,
    exitcode: Exit,
    netid: String,
    public: Ed25519Public,
    secret: Ed25519Secret,
    other: Ed25519Public)
  =>

    _out = out
    _set_exit = exitcode

    _public = public
    _secret = secret
    _other_public = other
    _netid = netid.array()
    _client_fsm = HandshakeClient(_public, _secret, _other_public, _netid)
    try
      (let _, let resp) = _client_fsm.step("")?
      _out.write(resp)
      _out.flush()
    end

  fun ref apply(parent: BufferedInput ref, data: Array[U8] iso): Bool =>
    try
      (let expect, let resp) = _client_fsm.step(String.from_iso_array(consume data))?
      if expect == 0 then
        let client = _client_fsm = HandshakeClient(_public, _secret, _other_public, _netid)
        let boxstream = client.boxstream()?
        let keys = boxstream.keys()
        _out.write(keys)
        _out.flush()
        false
      else
        _out.write(resp)
        _out.flush()
        parent.expect(expect)?
        true
      end
    else
      _set_exit(1)
      false
    end

// Follow from https://github.com/AljoschaMeyer/shs1-test
// Convert from Readline into normal input/output, with expect

use "cli"
use "term"
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
    Buffer(env.input, ClientInput(env.out, c.netid, pk, sk, c.server_id_pk), 1)

  fun server(env: Env, c: ServerConfig): InputNotify iso^ =>
    Buffer(env.input, ServerInput(env.out, c.netid, c.server_id_pk, c.server_id_sk))

interface tag InputActor
  be ready(term: ANSITerm)
  be apply(line: String, prompt: Promise[String])

class iso ServerInput is BufferedInputNotify
  let _out: OutStream

  let _netid: String
  let _public: Ed25519Public
  let _secret: Ed25519Secret
  let _server_fsm: HandshakeServer

  new iso create(out: OutStream, netid: String, public: Ed25519Public, secret: Ed25519Secret) =>
    _out = out
    _netid = netid
    _public = public
    _secret = secret
    _server_fsm = HandshakeServer.create(_public,_secret)
    try _server_fsm.init()? end

  fun ref apply(parent: BufferedInput ref, data: Array[U8] iso): Bool =>
    try
      let msg = String.from_iso_array(consume data)
      (let expect, let resp) = _server_fsm.step(String.from_array(Hex.decode(consume msg)?))?
      _out.print(resp)
      parent.expect(expect)?
      true
    else
      false
    end

class iso ClientInput is BufferedInputNotify
  let _out: OutStream

  let _netid: String
  let _public: Ed25519Public
  let _secret: Ed25519Secret
  let _other_public: Ed25519Public
  let _client_fsm: HandshakeClient

  new iso create(out: OutStream,
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

  fun ref apply(parent: BufferedInput ref, data: Array[U8] iso): Bool =>
    try
      let msg = String.from_iso_array(consume data)
      (let expect, let resp) = _client_fsm.step(String.from_array(Hex.decode(consume msg)?))?
      _out.print(resp)
      parent.expect(expect)?
      true
    else
      false
    end

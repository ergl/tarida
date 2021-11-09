use "ponytest"
use "ponycheck"

use "package:../tarida/shs"
use "package:../tarida/sodium"
use "package:../tarida_shs_integration"
use "package:../tarida/rpc"
use tarida = "package:../tarida"

actor Main is TestList
  new make() => None
  new create(env: Env) => PonyTest(env, this)
  fun tag tests(test: PonyTest) =>
    test(_TestSHS)
    test(Property1UnitTest[Array[U8]](_TestHexProperty))
    test(Property1UnitTest[Array[U8] iso](_TestCypherLinkProperty))
    test(Property1UnitTest[(I32, Bool, Bool, Array[U8])](_RPCArrEncodeProperty))
    test(Property1UnitTest[(I32, Bool, Bool, String)](_RPCStrEncodeProperty))

class iso _TestHexProperty is Property1[Array[U8]]
  fun name(): String => "hex/property"

  fun gen(): Generator[Array[U8]] =>
    Generators.array_of[U8](Generators.u8() where min = 64, max = 64)

  fun property(arg1: Array[U8], ph: PropertyHelper) =>
    try
      ph.assert_array_eq[U8](arg1, Hex.decode(Hex.encode(arg1))?)
    else
      ph.fail()
    end

class iso _RPCArrEncodeProperty is Property4[I32, Bool, Bool, Array[U8]]
  fun name(): String => "rpc_array_encode/property"

  fun gen1(): Generator[I32] => Generators.i32()
  fun gen2(): Generator[Bool] => Generators.bool()
  fun gen3(): Generator[Bool] => Generators.bool()
  fun gen4(): Generator[Array[U8]] =>
    Generators.array_of[U8](Generators.u8())

  fun property4(
    seq: I32,
    stream: Bool,
    err: Bool,
    data: Array[U8],
    ph: PropertyHelper)
  =>

    let iso_array = recover Array[U8](data.size()) end
    for byte in data.values() do
      iso_array.push(byte)
    end

    let header = RPCMsgHeader(seq, stream, err, BinaryMessage)
    // from message to bytes
    let bytes = RPCEncoder(recover RPCMsg(header, consume iso_array) end)
    let decoder = RPCDecoder(bytes.size())
    decoder.append(consume bytes)
    try
      match decoder.decode_msg()?
      | None => ph.fail()
      | Goodbye => ph.fail()
      | let msg: RPCMsg iso =>
        ph.assert_eq[I32](seq, msg.header().packet_number)
        ph.assert_eq[Bool](stream, msg.header().is_stream)
        ph.assert_eq[Bool](err, msg.header().is_end_error)
        ph.assert_is[RPCMsgTypeInfo](BinaryMessage, msg.header().type_info)
        ph.assert_array_eq[U8](data, ((consume msg).data() as Array[U8]))
      end
    else ph.fail() end

class iso _RPCStrEncodeProperty is Property4[I32, Bool, Bool, String]
  fun name(): String => "rpc_string_encode/property"

  fun gen1(): Generator[I32] => Generators.i32()
  fun gen2(): Generator[Bool] => Generators.bool()
  fun gen3(): Generator[Bool] => Generators.bool()
  fun gen4(): Generator[String] =>
    Generators.utf32_codepoint_string(Generators.u32())

  fun property4(
    seq: I32,
    stream: Bool,
    err: Bool,
    data: String,
    ph: PropertyHelper)
  =>

    let iso_data = data.clone()
    let header = RPCMsgHeader(seq, stream, err, StringMessage)
    // from message to bytes
    let bytes = RPCEncoder(recover RPCMsg(header, consume iso_data) end)
    let decoder = RPCDecoder(bytes.size())
    decoder.append(consume bytes)
    try
      match decoder.decode_msg()?
      | None => ph.fail()
      | Goodbye => ph.fail()
      | let msg: RPCMsg iso =>
        ph.assert_eq[I32](seq, msg.header().packet_number)
        ph.assert_eq[Bool](stream, msg.header().is_stream)
        ph.assert_eq[Bool](err, msg.header().is_end_error)
        ph.assert_is[RPCMsgTypeInfo](StringMessage, msg.header().type_info)
        let str_data = recover val (consume msg).data() as String ref end
        ph.assert_eq[String](data, str_data)
      end
    else ph.fail() end

class iso _TestCypherLinkProperty is Property1[Array[U8] iso]
  fun name(): String => "cypherlink/encode_decode/propery"

  fun gen(): Generator[Array[U8] iso] =>
    Generators.iso_seq_of[U8, Array[U8] iso](
        Generators.u8(),
        32,
        32
    )

  fun property(bytes': Array[U8] iso, ph: PropertyHelper) =>
    try
      let bytes = consume val bytes'
      let public_key = Sodium.ed25519_pk_from_bytes(bytes)?
      let cypherlink = tarida.Identity.cypherlink(public_key)
      let bytes_again = tarida.Identity.decode_cypherlink(consume cypherlink)?
      ph.assert_array_eq[U8](bytes, bytes_again)
    else
      ph.fail()
    end

class iso _TestSHS is UnitTest
  var _server_public: (Ed25519Public | None) = None
  var _server_secret: (Ed25519Secret | None) = None

  var _client_public: (Ed25519Public | None) = None
  var _client_secret: (Ed25519Secret | None) = None

  var _shs_server: (HandshakeServer | None) = None
  var _shs_client: (HandshakeClient | None) = None

  fun name(): String => "SHS Handshake"

  fun ref set_up(h: TestHelper)? =>
    (let spk, let ssk) = Sodium.ed25519_pair()?
    (let cpk, let csk) = Sodium.ed25519_pair()?

    _shs_server = HandshakeServer(spk, ssk, DefaultNetworkId()).>init()?
    _shs_client = HandshakeClient(cpk, csk, spk, DefaultNetworkId())

    (_server_public, _server_secret) = (spk, ssk)
    (_client_public, _client_secret) = (cpk, csk)

  fun ref apply(h: TestHelper) => try
    // client.send(hello)
    (let cl_expect_0, let client_hello) = (_shs_client as HandshakeClient).step("")?
    h.assert_eq[USize](64, cl_expect_0)
    h.assert_eq[USize](64, client_hello.size())

    // server.recv(hello); server.send(hello)
    (let s_expect_0, let server_hello) = (_shs_server as HandshakeServer).step(client_hello)?
    h.assert_eq[USize](112, s_expect_0)
    h.assert_eq[USize](64, server_hello.size())

    // client.recv(hello); client.send(client_auth)
    (let cl_expect_1, let client_auth) = (_shs_client as HandshakeClient).step(server_hello)?
    h.assert_eq[USize](80, cl_expect_1)
    h.assert_eq[USize](112, client_auth.size())

    // serbver.recv(client_auth); server.send(server_accept)
    (let s_expect_1, let server_accept) = (_shs_server as HandshakeServer).step(client_auth)?
    h.assert_eq[USize](0, s_expect_1) // Server is done
    h.assert_eq[USize](80, server_accept.size())

    (let cl_expect_2, let empty) = (_shs_client as HandshakeClient).step(server_accept)?
    h.assert_eq[USize](0, cl_expect_2) // Client is done
    h.assert_eq[USize](0, empty.size()) // Client doesn't reply to this

    // Now both server and client should error if trying to advance
    try (_shs_server as HandshakeServer).step("")?; h.fail()
    else h.assert_true(true) end

    try (_shs_client as HandshakeClient).step("")?; h.fail()
    else h.assert_true(true) end

    var maybe_client = try
        _shs_client = HandshakeClient(
          _client_public as Ed25519Public,
          _client_secret as Ed25519Secret,
          _server_public as Ed25519Public,
          DefaultNetworkId()
        )
      else
        None
    end

    match (maybe_client = None)
    | let c: HandshakeClient =>
        try
          let keys = c.boxstream()?.keys()
          h.assert_eq[USize](112, keys.size())
        else h.assert_true(false) end
    end

  else h.fail() end

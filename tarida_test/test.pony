use "ponytest"
use "package:../tarida/shs"
use "package:../tarida/sodium"

actor Main is TestList
  new make() => None
  new create(env: Env) => PonyTest(env, this)
  fun tag tests(test: PonyTest) =>
    test(_TestSHS)

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

    _shs_server = HandshakeServer(spk, ssk).>init()?
    _shs_client = HandshakeClient(cpk, csk, spk)

    (_server_public, _server_secret) = (spk, ssk)
    (_client_public, _client_secret) = (cpk, csk)

  fun ref apply(h: TestHelper) => try
    (let cl_expect_0, let client_hello) = (_shs_client as HandshakeClient).step("")?
    h.assert_eq[USize](64, cl_expect_0)
    h.assert_eq[USize](64, client_hello.size())

    (let s_expect_0, let server_hello) = (_shs_server as HandshakeServer).step(client_hello)?
    h.assert_eq[USize](112, s_expect_0)
    h.assert_eq[USize](64, server_hello.size())

    (let cl_expect_1, let client_auth) = (_shs_client as HandshakeClient).step(server_hello)?
    h.assert_eq[USize](80, cl_expect_1)
    h.assert_eq[USize](112, client_auth.size())

  else h.fail() end

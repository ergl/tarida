use "debug"
use "package:../sodium"

primitive _Init
primitive _ServerHello
primitive _ServerAccept
primitive _ClientDone
type _ClientFSM is (_Init | _ServerHello | _ServerAccept | _ClientDone)

// TODO(borja): Handle code duplication w/ https://patterns.ponylang.io/code-sharing/mixin.html
// Also, consider changing the implementation to use type states,
// aking to something like http://cliffle.com/blog/rust-typestate/
class iso HandshakeClient
  let _network_id: Array[U8] val

  var _state: _ClientFSM

  let _id_pk: Ed25519Public
  let _id_sk: Ed25519Secret
  let _other_id_pk: Ed25519Public

  var _eph_pk: (Curve25519Public | None) = None
  var _eph_sk: (Curve25519Secret | None) = None

  var _other_eph_pk: (Curve25519Public | None) = None

  var _shared_secret_1: (_SharedSecret1 | None) = None
  var _shared_secret_2: (_SharedSecret2 | None) = None
  var _shared_secret_3: (_SharedSecret3 | None) = None

  var _self_detached_sign: (_ClientDetachedSign | None) = None
  var _server_detached_sign: (_ServerDetachedSign | None) = None

  new iso create(
    pk: Ed25519Public,
    sk: Ed25519Secret,
    other_id_pk: Ed25519Public,
    network_id: Array[U8] val)
  =>
    _network_id = network_id
    _id_pk = pk
    _id_sk = sk
    _other_id_pk = other_id_pk
    _state = _Init

  fun ref step(msg: String): (USize, String)? =>
    match _state
    | _Init =>
      _state = _ServerHello
      Debug.err("HandshakeClient _Init")
      (64, _client_hello(msg)?)

    | _ServerHello =>
      _verify_hello(msg)?
      _state = _ServerAccept
      Debug.err("HandshakeClient _ServerHello")
      (80, _client_auth()?)

    | _ServerAccept =>
      _state = _ClientDone
      _verify_server_accept(msg)?
      Debug.err("HandshakeClient _ServerAccept")
      (0, "")

    | _ClientDone => error // Shouldn't reuse the client
    end

  fun _full_secret(): BoxStream^? =>
    if _state isnt _ClientDone then error end

    let secret = _Handshake.make_secret(
      _shared_secret_1 as _SharedSecret1,
      _shared_secret_2 as _SharedSecret2,
      _shared_secret_3 as _SharedSecret3,
      _network_id
    )

    _Handshake.make_box_keys(
      secret,
      _id_pk,
      _other_id_pk,
      _eph_pk as Curve25519Public,
      _other_eph_pk as Curve25519Public,
      _network_id
    )?

  fun ref _client_hello(seed: String): String? =>
    let eph_pair = Sodium.curve25519_pair_seed(seed)?
    (_eph_pk, _eph_sk) = eph_pair
    _Handshake.hello_challenge(eph_pair._1, _network_id)?

  fun ref _verify_hello(msg: String)? =>
    let other_eph_pk = _Handshake.hello_verify(msg, _network_id)?
    let secrets = _Handshake.client_derive_secret_1(
      _eph_sk as Curve25519Secret,
      other_eph_pk, // Notice server's public key here
      _other_id_pk
    )?

    _other_eph_pk = other_eph_pk
    _shared_secret_1 = secrets._1
    _shared_secret_2 = secrets._2
    // Inline second secret derivation here
    _shared_secret_3 = _Handshake.client_derive_secret_2(
      _id_sk,
      other_eph_pk
    )?

  fun ref _client_auth(): String? =>
    let short_term_ss = _shared_secret_1 as _SharedSecret1
    let long_term_ss = _shared_secret_2 as _SharedSecret2

    let detached_sign = _Handshake.client_detached_sign(_other_id_pk, _id_sk, short_term_ss, _network_id)?
    _self_detached_sign = detached_sign
    _Handshake.client_auth(detached_sign, _id_pk, short_term_ss, long_term_ss, _network_id)?

  fun ref _verify_server_accept(msg: String)? =>
    _server_detached_sign = _Handshake.server_accept_verify(
      where enc = msg,
      client_id_pk = _id_pk,
      server_id_pk = _other_id_pk,
      client_sign = _self_detached_sign as _ClientDetachedSign,
      short_term_ss = _shared_secret_1 as _SharedSecret1,
      long_term_ss_1 = _shared_secret_2 as _SharedSecret2,
      long_term_ss_2 = _shared_secret_3 as _SharedSecret3,
      net_id = _network_id
    )?

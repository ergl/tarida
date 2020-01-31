use "debug"
use "package:../sodium"

primitive _Init
primitive _ServerHello
primitive _ServerAccept
type _ClientFSM is (_Init | _ServerHello | _ServerAccept)

// TODO(borja): Handle code duplication w/ https://patterns.ponylang.io/code-sharing/mixin.html
class iso HandshakeClient
  var _state: _ClientFSM

  let _id_pk: Ed25519Public
  let _id_sk: Ed25519Secret
  let _other_id_pk: Ed25519Public

  var _eph_pk: (Curve25519Public | None) = None
  var _eph_sk: (Curve25519Secret | None) = None

  var _other_eph_pk: (Curve25519Public | None) = None

  var _short_term_shared_secret: (_ShortTermSS | None) = None
  var _long_term_shared_secret: (_LongTermSS | None) = None
  var _self_detached_sign: (_ClientDetachedSign | None) = None

  new iso create(pk: Ed25519Public, sk: Ed25519Secret, other_id_pk: Ed25519Public) =>
    _id_pk = pk
    _id_sk = sk
    _other_id_pk = other_id_pk
    _state = _Init

  fun ref step(msg: String): (USize, String)? =>
    match _state
    | _Init =>
      Debug.out("HandshakeClient _Init")
      _state = _ServerHello
      (64, _client_hello()?)

    | _ServerHello =>
      Debug.out("HandshakeClient _ServerHello")
      _state = _ServerAccept
      _verify_hello(msg)?
      (80, _client_auth()?)

    | _ServerAccept =>
      Debug.out("HandshakeClient _ServerAccept")
      (0, "")
    end

  fun ref _client_hello(): String? =>
    let eph_pair = Sodium.curve25519_pair()?
    (_eph_pk, _eph_sk) = eph_pair
    _Handshake.hello_challenge(eph_pair._1)?

  fun ref _verify_hello(msg: String)? =>
    let other_eph_pk = _Handshake.hello_verify(msg)?
    let secrets = _Handshake.client_derive_secret(
      _eph_sk as Curve25519Secret,
      other_eph_pk, // Notice server's public key here
      _other_id_pk
    )?

    _other_eph_pk = other_eph_pk
    _short_term_shared_secret = secrets._1
    _long_term_shared_secret = secrets._2

  fun ref _client_auth(): String? =>
    let short_term_ss = _short_term_shared_secret as _ShortTermSS
    let long_term_ss = _long_term_shared_secret as _LongTermSS

    let detached_sign = _Handshake.client_detached_sign(_other_id_pk, _id_sk, short_term_ss)?
    _self_detached_sign = detached_sign
    _Handshake.client_auth(detached_sign, _id_pk, short_term_ss, long_term_ss)?

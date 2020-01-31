use "debug"
use "package:../sodium"

primitive _ClientHello
primitive _ClientAuth
primitive _Done
type _ServerFSM is (_ClientHello | _ClientAuth | _Done)

class iso HandshakeServer
  var _state: _ServerFSM

  let _id_pk: Ed25519Public
  let _id_sk: Ed25519Secret
  // Learned during client auth
  var _other_id_pk: (Ed25519Public | None) = None

  var _eph_pk: (Curve25519Public | None) = None
  var _eph_sk: (Curve25519Secret | None) = None

  var _other_eph_pk: (Curve25519Public | None) = None

  var _short_term_shared_secret: (_ShortTermSS | None) = None
  var _long_term_shared_secret: (_LongTermServerSS | None) = None
  var _client_detached_sign: (_ClientDetachedSign | None) = None

  new iso create(pk: Ed25519Public, sk: Ed25519Secret) =>
    _id_pk = pk
    _id_sk = sk
    _state = _ClientHello

  fun ref init(): USize? =>
    (_eph_pk, _eph_sk) = Sodium.curve25519_pair()?
    64

  // Return the number of bytes to expect for the next call, along
  // with the output of this step. If the byte size is 0, we're done
  // It might error if some of the verifications are wrong
  fun ref step(msg: String): (USize, String)? =>
    match _state
    | _ClientHello =>
      _verify_hello(msg)?
      _state = _ClientAuth
      Debug.out("HandshakeServer _ClientHello")
      (112, _server_hello()?)

    | _ClientAuth =>
      _verify_client_auth(msg)?
      _state = _Done
      Debug.out("HandshakeServer _ClientAuth")
      (0, "") // TODO
    | _Done => error // Shouldn't reuse the server
    end

  fun ref _verify_hello(msg: String)? =>
    let other_eph_pk = _Handshake.hello_verify(msg)?
    let secrets = _Handshake.server_derive_secret(
      _id_sk,
      _eph_sk as Curve25519Secret,
      other_eph_pk
    )?

    _other_eph_pk = other_eph_pk
    _short_term_shared_secret = secrets._1
    _long_term_shared_secret = secrets._2

  fun ref _server_hello(): String? =>
    _Handshake.hello_challenge(_eph_pk as Curve25519Public)?

  fun ref _verify_client_auth(msg: String)? =>
    (_client_detached_sign, _other_id_pk) = _Handshake.client_auth_verify(
      msg,
      _id_pk,
      _short_term_shared_secret as _ShortTermSS,
      _long_term_shared_secret as _LongTermServerSS
    )?

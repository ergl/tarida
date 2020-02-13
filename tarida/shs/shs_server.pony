use "debug"
use "package:../sodium"

primitive _ClientHello
primitive _ClientAuth
primitive _ServerDone
type _ServerFSM is (_ClientHello | _ClientAuth | _ServerDone)

class iso HandshakeServer
  let _network_id: Array[U8] val

  var _state: _ServerFSM

  let _id_pk: Ed25519Public
  let _id_sk: Ed25519Secret
  // Learned during client auth
  var _other_id_pk: (Ed25519Public | None) = None

  var _eph_pk: (Curve25519Public | None) = None
  var _eph_sk: (Curve25519Secret | None) = None

  var _other_eph_pk: (Curve25519Public | None) = None

  var _shared_secret_1: (_SharedSecret1 | None) = None
  var _shared_secret_2: (_SharedSecret2 | None) = None
  var _shared_secret_3: (_SharedSecret3 | None) = None

  var _client_detached_sign: (_ClientDetachedSign | None) = None
  var _server_detached_sign: (_ServerDetachedSign | None) = None

  new iso create(
    pk: Ed25519Public,
    sk: Ed25519Secret,
    network_id: Array[U8] val)
  =>
    _network_id = network_id
    _id_pk = pk
    _id_sk = sk
    _state = _ClientHello

  // FIXME(borja): Maybe return a capability from this
  // Since SHSServer shouldn't be used without calling init first, we could
  // return a capability here, and require it as an argument for every call,
  // so we never forget to call it.
  fun ref init(): USize? =>
    (_eph_pk, _eph_sk) = Sodium.curve25519_pair()?
    64

  fun ref init_seed(seed: String): USize? =>
    (_eph_pk, _eph_sk) = Sodium.curve25519_pair_seed(seed)?
    64

  // Return the number of bytes to expect for the next call, along
  // with the output of this step. If the byte size is 0, we're done
  // It might error if some of the verifications are wrong
  fun ref step(msg: String): (USize, String)? =>
    match _state
    | _ClientHello =>
      _verify_hello(msg)?
      _state = _ClientAuth
      Debug.err("HandshakeServer _ClientHello")
      (112, _server_hello()?)

    | _ClientAuth =>
      _verify_client_auth(msg)?
      _state = _ServerDone
      Debug.err("HandshakeServer _ClientAuth")
      (0, _server_accept()?)
    | _ServerDone => error // Shouldn't reuse the server
    end

  fun _full_secret(): BoxStream^? =>
    if _state isnt _ServerDone then error end

    let secret = _Handshake.make_secret(
      _shared_secret_1 as _SharedSecret1,
      _shared_secret_2 as _SharedSecret2,
      _shared_secret_3 as _SharedSecret3,
      _network_id
    )

    _Handshake.make_box_keys(
      secret,
      _id_pk,
      _other_id_pk as Ed25519Public,
      _eph_pk as Curve25519Public,
      _other_eph_pk as Curve25519Public,
      _network_id
    )?

  fun ref _verify_hello(msg: String)? =>
    let other_eph_pk = _Handshake.hello_verify(msg, _network_id)?
    let secrets = _Handshake.server_derive_secret_1(
      _id_sk,
      _eph_sk as Curve25519Secret,
      other_eph_pk
    )?

    _other_eph_pk = other_eph_pk
    _shared_secret_1 = secrets._1
    _shared_secret_2 = secrets._2

  fun _server_hello(): String? =>
    _Handshake.hello_challenge(_eph_pk as Curve25519Public, _network_id)?

  fun ref _verify_client_auth(msg: String)? =>
    let results = _Handshake.client_auth_verify(
      msg,
      _id_pk,
      _shared_secret_1 as _SharedSecret1,
      _shared_secret_2 as _SharedSecret2,
      _network_id
    )?

    _client_detached_sign = results._1
    _other_id_pk = results._2
    // Now that we have the client's public key, derive secret
    _shared_secret_3 = _Handshake.server_derive_secret_2(
      _eph_sk as Curve25519Secret,
      _other_id_pk as Ed25519Public
    )?

  fun ref _server_accept(): String? =>
    let shared_secret_1 = _shared_secret_1 as _SharedSecret1
    let sign = _Handshake.server_detached_sign(
        _id_sk,
        _other_id_pk as Ed25519Public,
        _client_detached_sign as _ClientDetachedSign,
        shared_secret_1,
        _network_id
    )?

    _server_detached_sign = sign

    let shared_secret_2 = _shared_secret_2 as _SharedSecret2
    let shared_secret_3 = _shared_secret_3 as _SharedSecret3
    _Handshake.server_accept(
      sign,
      shared_secret_1,
      shared_secret_2,
      shared_secret_3,
      _network_id
    )?

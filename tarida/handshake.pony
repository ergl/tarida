use "debug"
use "crypto"
use "sodium"

primitive _ClientHello
primitive _ClientAuth
type _ServerFSM is (_ClientHello | _ClientAuth)

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

  var _short_term_shared_secret: (ByteSeq | None) = None
  var _long_term_shared_secret: (ByteSeq | None) = None

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
    Handshake.hello_challenge(eph_pair._1)?

  fun ref _verify_hello(msg: String)? =>
    let other_eph_pk = Handshake.hello_verify(msg)?
    let secrets = Handshake.client_derive_secret(
      _eph_sk as Curve25519Secret,
      other_eph_pk, // Notice server's public key here
      _other_id_pk
    )?

    _other_eph_pk = other_eph_pk
    _short_term_shared_secret = secrets._1
    _long_term_shared_secret = secrets._2

  fun ref _client_auth(): String? =>
    let short_term_ss = _short_term_shared_secret as ByteSeq
    let long_term_ss = _long_term_shared_secret as ByteSeq

    let detached_sign = Handshake.client_detached_sign(_other_id_pk, _id_sk, short_term_ss)?
    Handshake.client_auth(detached_sign, _id_pk, short_term_ss, long_term_ss)?

class iso HandshakeServer
  var _state: _ServerFSM

  let _id_pk: Ed25519Public
  let _id_sk: Ed25519Secret

  var _eph_pk: (Curve25519Public | None) = None
  var _eph_sk: (Curve25519Secret | None) = None

  var _other_eph_pk: (Curve25519Public | None) = None

  var _short_term_shared_secret: (ByteSeq | None) = None
  var _long_term_shared_secret: (ByteSeq | None) = None

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
      Debug.out("HandshakeServer _ClientHello")
      _state = _ClientAuth
      (112, _do_hello(msg)?)

    | _ClientAuth =>
      Debug.out("HandshakeServer _ClientAuth?")
      (0, "")
    end

  fun ref _do_hello(msg: String): String? =>
    let other_eph_pk = Handshake.hello_verify(msg)?
    let resp = Handshake.hello_challenge(_eph_pk as Curve25519Public)?
    let secrets = Handshake.server_derive_secret(
      _id_sk,
      _eph_sk as Curve25519Secret,
      other_eph_pk
    )?

    _other_eph_pk = other_eph_pk
    _short_term_shared_secret = secrets._1
    _long_term_shared_secret = secrets._2

    resp

primitive Handshake
  fun network_id(): Array[U8] val =>
    [as U8: 0xd4; 0xa1; 0xcb; 0x88
            0xa6; 0x6f; 0x02; 0xf8
            0xdb; 0x63; 0x5c; 0xe2
            0x64; 0x41; 0xcc; 0x5d
            0xac; 0x1b; 0x08; 0x42
            0x0c; 0xea; 0xac; 0x23
            0x08; 0x39; 0xb7; 0x55
            0x84; 0x5a; 0x9f; 0xfb]

  fun hello_challenge(pk: Curve25519Public): String? =>
    let auth = Sodium.auth_msg(pk.string(), network_id())?
    recover String.create(auth.size() + pk.size())
                  .>append(auth).>append(pk)
    end

  fun hello_verify(msg: String): Curve25519Public? =>
    if msg.size() != 64 then error end

    let other_hmac = msg.trim(0, 31)
    let other_eph_pk = msg.trim(32) // until the end

    let valid = Sodium.auth_msg_verify(
      where auth_tag = other_hmac,
      msg = other_eph_pk,
      key = network_id()
    )

    if not valid then error end
    Curve25519Public(other_eph_pk.clone().iso_array())

  // Must be only called from server
  fun server_derive_secret(
    id_sk: Ed25519Secret,
    eph_sk: Curve25519Secret,
    other_eph_sk: Curve25519Public)
    : (ByteSeq, ByteSeq)?
  =>

    let short_term_ss = Sodium.scalar_mult(
      eph_sk.string(),
      other_eph_sk.string()
    )?

    let long_term_ss = Sodium.scalar_mult(
      Sodium.ed25519_sk_to_curve25519(id_sk)?.string(),
      other_eph_sk.string()
    )?

    (short_term_ss, long_term_ss)

  // Must be only called from client
  fun client_derive_secret(
    eph_sk: Curve25519Secret,
    other_eph_pk: Curve25519Public,
    other_id_pub: Ed25519Public)
    : (ByteSeq, ByteSeq)?
  =>

    let short_term_ss = Sodium.scalar_mult(
      eph_sk.string(),
      other_eph_pk.string()
    )?

    let long_term_ss = Sodium.scalar_mult(
      eph_sk.string(),
      Sodium.ed25519_pk_to_curve25519(other_id_pub)?.string()
    )?

    (short_term_ss, long_term_ss)

  fun client_detached_sign(
    server_pk: Ed25519Public,
    id_sk: Ed25519Secret,
    short_term_ss: ByteSeq)
    : ByteSeq?
  =>

    let net_id = network_id()
    let hashed_ss = SHA256(short_term_ss)
    let msg_size = net_id.size() + server_pk.size() + hashed_ss.size()
    let msg = recover
      String.create(msg_size)
            .>append(String.from_array(net_id))
            .>append(server_pk.string())
            .>append(String.from_array(hashed_ss))
    end

    (let detached, _) = Sodium.sign_detached(consume msg, id_sk.string())?
    detached

  fun client_auth(
    detached_sign: ByteSeq,
    id_pk: Ed25519Public,
    short_term_ss: ByteSeq,
    long_term_ss: ByteSeq)
    : String?
  =>
    let net_id = network_id()
    let msg = recover
      String.create(detached_sign.size() + id_pk.size())
            .>append(detached_sign)
            .>append(id_pk.string())
    end
    let raw_key = recover
      String.create(net_id.size() + short_term_ss.size() + long_term_ss.size())
            .>append(String.from_array(net_id))
            .>append(short_term_ss)
            .>append(long_term_ss)
    end
    let key = SHA256(consume raw_key)
    // OK to use since this is the only time we encrypt this message
    let nonce = recover Array[U8].init(0, 24) end
    String.from_array(Sodium.box_easy(consume msg, consume key, consume nonce)?)

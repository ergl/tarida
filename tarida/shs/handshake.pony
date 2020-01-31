use "debug"
use "crypto"
use "package:../sodium"

interface val _OpaqueString
  fun _get_inner(): String
  fun cpointer(): Pointer[U8] tag => _get_inner().cpointer()
  fun size(): USize => _get_inner().size()
  fun string(): String => _get_inner()

class val _ShortTermSS is _OpaqueString
  let _inner: String val
  new val create(from: String val) => _inner = from
  fun _get_inner(): String => _inner

class val _LongTermSS is _OpaqueString
  let _inner: String val
  new val create(from: String val) => _inner = from
  fun _get_inner(): String => _inner

class val _ClientDetachedSign is _OpaqueString
  let _inner: String val
  new val create(from: String val) => _inner = from
  fun _get_inner(): String => _inner

primitive _Handshake
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
    : (_ShortTermSS, _LongTermSS)?
  =>

    let short_term_ss = Sodium.scalar_mult(
      eph_sk.string(),
      other_eph_sk.string()
    )?

    let long_term_ss = Sodium.scalar_mult(
      Sodium.ed25519_sk_to_curve25519(id_sk)?.string(),
      other_eph_sk.string()
    )?

    (_ShortTermSS(short_term_ss), _LongTermSS(long_term_ss))

  // Must be only called from client
  fun client_derive_secret(
    eph_sk: Curve25519Secret,
    other_eph_pk: Curve25519Public,
    other_id_pub: Ed25519Public)
    : (_ShortTermSS, _LongTermSS)?
  =>

    let short_term_ss = Sodium.scalar_mult(
      eph_sk.string(),
      other_eph_pk.string()
    )?

    let long_term_ss = Sodium.scalar_mult(
      eph_sk.string(),
      Sodium.ed25519_pk_to_curve25519(other_id_pub)?.string()
    )?

    (_ShortTermSS(short_term_ss), _LongTermSS(long_term_ss))

  fun client_detached_sign(
    server_pk: Ed25519Public,
    id_sk: Ed25519Secret,
    short_term_ss: _ShortTermSS)
    : _ClientDetachedSign?
  =>

    let net_id = network_id()
    let hashed_ss = SHA256(short_term_ss.string())
    let msg_size = net_id.size() + server_pk.size() + hashed_ss.size()
    let msg = recover
      String.create(msg_size)
            .>append(String.from_array(net_id))
            .>append(server_pk.string())
            .>append(String.from_array(hashed_ss))
    end

    (let detached, _) = Sodium.sign_detached(consume msg, id_sk.string())?
    _ClientDetachedSign(detached)

  fun client_auth(
    detached_sign: _ClientDetachedSign,
    id_pk: Ed25519Public,
    short_term_ss: _ShortTermSS,
    long_term_ss: _LongTermSS)
    : String?
  =>
    let net_id = network_id()
    let msg = recover
      String.create(detached_sign.size() + id_pk.size())
            .>append(detached_sign.string())
            .>append(id_pk.string())
    end
    let raw_key = recover
      String.create(net_id.size() + short_term_ss.size() + long_term_ss.size())
            .>append(String.from_array(net_id))
            .>append(short_term_ss.string())
            .>append(long_term_ss.string())
    end
    let key = SHA256(consume raw_key)
    // OK to use since this is the only time we encrypt this message
    let nonce = recover Array[U8].init(0, 24) end
    Sodium.box_easy(consume msg, consume key, consume nonce)?

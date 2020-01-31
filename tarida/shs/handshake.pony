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

class val _LongTermServerSS is _OpaqueString
  let _inner: String val
  new val create(from: String val) => _inner = from
  fun _get_inner(): String => _inner

class val _LongTermClientSS is _OpaqueString
  let _inner: String val
  new val create(from: String val) => _inner = from
  fun _get_inner(): String => _inner

class val _ClientDetachedSign is _OpaqueString
  let _inner: String val
  new val create(from: String val) => _inner = from
  fun _get_inner(): String => _inner

class val _ServerDetachedSign is _OpaqueString
  let _inner: String val
  new val create(from: String val) => _inner = from
  fun _get_inner(): String => _inner

class val _BareBoxStreamSecret is _OpaqueString
  let _inner: String val
  new val create(from: String val) => _inner = from
  fun _get_inner(): String => _inner

class val _BoxStreamEncKey is _OpaqueString
  let _inner: String val
  new val create(from: String val) => _inner = from
  fun _get_inner(): String => _inner

class val _BoxStreamEncNonce is _OpaqueString
  let _inner: String val
  new val create(from: String val) => _inner = from
  fun _get_inner(): String => _inner

class val _BoxStreamDecKey is _OpaqueString
  let _inner: String val
  new val create(from: String val) => _inner = from
  fun _get_inner(): String => _inner

class val _BoxStreamDecNonce is _OpaqueString
  let _inner: String val
  new val create(from: String val) => _inner = from
  fun _get_inner(): String => _inner

type _BoxKeys is (_BoxStreamEncKey, _BoxStreamEncNonce, _BoxStreamDecKey, _BoxStreamDecNonce)

// TODO(borja): Plug integration tests from https://github.com/AljoschaMeyer/shs1-test
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
  fun server_derive_secret_1(
    id_sk: Ed25519Secret,
    eph_sk: Curve25519Secret,
    other_eph_pk: Curve25519Public)
    : (_ShortTermSS, _LongTermServerSS)?
  =>

    let short_term_ss = Sodium.scalar_mult(
      eph_sk.string(),
      other_eph_pk.string()
    )?

    let long_term_ss = Sodium.scalar_mult(
      Sodium.ed25519_sk_to_curve25519(id_sk)?.string(),
      other_eph_pk.string()
    )?

    (_ShortTermSS(short_term_ss), _LongTermServerSS(long_term_ss))

  // Must be only called from client
  fun client_derive_secret_1(
    eph_sk: Curve25519Secret,
    other_eph_pk: Curve25519Public,
    other_id_pk: Ed25519Public)
    : (_ShortTermSS, _LongTermServerSS)?
  =>

    let short_term_ss = Sodium.scalar_mult(
      eph_sk.string(),
      other_eph_pk.string()
    )?

    let long_term_ss = Sodium.scalar_mult(
      eph_sk.string(),
      Sodium.ed25519_pk_to_curve25519(other_id_pk)?.string()
    )?

    (_ShortTermSS(short_term_ss), _LongTermServerSS(long_term_ss))

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
    long_term_ss: _LongTermServerSS)
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

  fun client_auth_verify(
    enc: String,
    id_pk: Ed25519Public,
    short_term_ss: _ShortTermSS,
    long_term_ss: _LongTermServerSS)
    : (_ClientDetachedSign, Ed25519Public)?
  =>

    let net_id = network_id()
    // OK to use since this is the only time we encrypt this message
    let nonce = recover Array[U8].init(0, 24) end
    let key_raw = recover
      String.create(net_id.size() + short_term_ss.size() + long_term_ss.size())
            .>append(String.from_array(net_id))
            .>append(short_term_ss.string())
            .>append(long_term_ss.string())
    end
    let key = SHA256(consume key_raw)

    let plain_text = Sodium.box_easy_open(enc, consume key, consume nonce)?
    if plain_text.size() != 96 then error end // Spec

    let sign_detached = plain_text.trim(0, 63)
    let client_id_pk = plain_text.trim(64) // until the end

    let hashed_ss = SHA256(short_term_ss.string())
    let msg = recover
      String.create(net_id.size() + id_pk.size() + hashed_ss.size())
            .>append(String.from_array(net_id))
            .>append(id_pk.string())
            .>append(String.from_array(hashed_ss))
    end

    let valid = Sodium.sign_detached_verify(
      where sig = sign_detached,
      msg = consume msg,
      key = client_id_pk
    )

    if not valid then error end
    (_ClientDetachedSign(sign_detached), Ed25519Public.from_string(client_id_pk))

  fun client_derive_secret_2(id_sk: Ed25519Secret, other_eph_pk: Curve25519Public): _LongTermClientSS? =>
    _LongTermClientSS(Sodium.scalar_mult(
      Sodium.ed25519_sk_to_curve25519(id_sk)?.string(),
      other_eph_pk.string()
    )?)

  fun server_derive_secret_2(eph_sk: Curve25519Secret, other_id_pk: Ed25519Public): _LongTermClientSS? =>
    _LongTermClientSS(Sodium.scalar_mult(
      eph_sk.string(),
      Sodium.ed25519_pk_to_curve25519(other_id_pk)?.string()
    )?)

  fun server_detached_sign(
    server_id_sk: Ed25519Secret,
    client_id_pk: Ed25519Public,
    client_sign: _ClientDetachedSign,
    short_term_ss: _ShortTermSS)
    : _ServerDetachedSign?
  =>

    let net_id = network_id()
    let hashed_ss = SHA256(short_term_ss.string())
    let msg_size = net_id.size() + client_sign.size() + client_id_pk.size() + hashed_ss.size()
    let msg = recover
      String.create(msg_size)
            .>append(String.from_array(net_id))
            .>append(client_sign.string())
            .>append(client_id_pk.string())
            .>append(hashed_ss)
    end

    (let detached, _) = Sodium.sign_detached(consume msg, server_id_sk.string())?
    _ServerDetachedSign(detached)

  fun server_accept(
    server_sign: _ServerDetachedSign,
    short_term_ss: _ShortTermSS,
    long_term_ss_1: _LongTermServerSS,
    long_term_ss_2: _LongTermClientSS)
    : String?
  =>

    let net_id = network_id()
    let key_size = net_id.size() + short_term_ss.size() + long_term_ss_1.size() + long_term_ss_2.size()
    let raw_key = recover
      String.create(key_size)
            .>append(String.from_array(net_id))
            .>append(short_term_ss.string())
            .>append(long_term_ss_1.string())
            .>append(long_term_ss_2.string())
    end
    let key = SHA256(consume raw_key)
    // OK to use since this is the only time we encrypt this message
    let nonce = recover Array[U8].init(0, 24) end
    Sodium.box_easy(server_sign.string(), consume key, consume nonce)?

  // TODO(borja): Consider splitting function
  fun server_accept_verify(
    enc: String,
    client_id_pk: Ed25519Public,
    server_id_pk: Ed25519Public,
    client_sign: _ClientDetachedSign,
    short_term_ss: _ShortTermSS,
    long_term_ss_1: _LongTermServerSS,
    long_term_ss_2: _LongTermClientSS)
    : _ServerDetachedSign?
  =>
    let net_id = network_id()
    // OK to use since this is the only time we encrypt this message
    let nonce = recover Array[U8].init(0, 24) end
    let key_size = net_id.size() + short_term_ss.size() + long_term_ss_1.size() + long_term_ss_2.size()
    let raw_key = recover
      String.create(key_size)
            .>append(String.from_array(net_id))
            .>append(short_term_ss.string())
            .>append(long_term_ss_1.string())
            .>append(long_term_ss_2.string())
    end
    let key = SHA256(consume raw_key)

    let server_sign = Sodium.box_easy_open(enc, consume key, consume nonce)?

    let hashed_ss = SHA256(short_term_ss.string())
    let msg_size = net_id.size() + client_sign.size() + client_id_pk.size() + hashed_ss.size()
    let msg = recover
      String.create(msg_size)
            .>append(String.from_array(net_id))
            .>append(client_sign.string())
            .>append(client_id_pk.string())
            .>append(String.from_array(hashed_ss))
    end

    let valid = Sodium.sign_detached_verify(
      where sig = server_sign,
      msg = consume msg,
      key = server_id_pk.string()
    )

    if not valid then error end
    _ServerDetachedSign(server_sign)

  fun make_secret(
    ss_1: _ShortTermSS,
    ss_2: _LongTermServerSS,
    ss_3: _LongTermClientSS)
    : _BareBoxStreamSecret?
  =>

    let net_id = network_id()
    let msg_size = net_id.size() + ss_1.size() + ss_2.size() + ss_3.size()
    if msg_size != 1024 then error end // Spec
    let msg = recover
      String.create(msg_size)
            .>append(ss_1.string())
            .>append(ss_2.string())
            .>append(ss_3.string())
    end

    _BareBoxStreamSecret(String.from_array(SHA256(SHA256(consume msg))))

  fun make_box_keys(
    secret: _BareBoxStreamSecret,
    self_id_pk: Ed25519Public,
    other_id_pk: Ed25519Public,
    self_eph_pk: Curve25519Public,
    other_eph_pk: Curve25519Public)
    : _BoxKeys?
  =>

    let net_id = network_id()
    let enc_k = String.from_array(SHA256(recover
      String.create(secret.size() + other_id_pk.size())
            .>append(secret.string())
            .>append(other_id_pk.string())
    end))

    let enc_nonce = Sodium.auth_msg(
      other_eph_pk.string().trim(0, 23),
      String.from_array(net_id)
    )?

    let dec_k = String.from_array(SHA256(recover
      String.create(secret.size() + self_id_pk.size())
            .>append(secret.string())
            .>append(self_id_pk.string())
    end))

    let dec_nonce = Sodium.auth_msg(
      self_eph_pk.string().trim(0, 23),
      String.from_array(net_id)
    )?

    (_BoxStreamEncKey(enc_k), _BoxStreamEncNonce(enc_nonce), _BoxStreamDecKey(dec_k), _BoxStreamDecNonce(dec_nonce))

use "debug"
use "crypto"
use "package:../sodium"

interface val _OpaqueString
  fun _get_inner(): String
  fun cpointer(): Pointer[U8] tag => _get_inner().cpointer()
  fun size(): USize => _get_inner().size()
  fun string(): String => _get_inner()

class val _SharedSecret1 is _OpaqueString
  let _inner: String val
  new val create(from: String val) => _inner = from
  fun _get_inner(): String => _inner

class val _SharedSecret2 is _OpaqueString
  let _inner: String val
  new val create(from: String val) => _inner = from
  fun _get_inner(): String => _inner

class val _SharedSecret3 is _OpaqueString
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

class val _BoxStreamDecKey is _OpaqueString
  let _inner: String val
  new val create(from: String val) => _inner = from
  fun _get_inner(): String => _inner

// FIXME(borja): Figure out what to do if we reuse nonces. Should we crash?
interface iso _InPlaceNonce
  fun ref next()
  fun as_nonce(): String

// FIXME(borja): Too much cloning, allocs on every message
// TODO(borja): Double buffer
// Instead of allocating on every call to `as_nonce`, we could
// have two buffers, already allocated. In `as_nonce`, we use
// destructive read to give away an already allocated copy
// Can we do this?
class iso _BoxStreamEncNonce is _InPlaceNonce
  var _current: Array[U8]
  new iso create(from: String) => _current = from.clone().iso_array()
  fun ref next() =>
    try
      var idx: USize = _current.size() - 1
      var before: U8 = 0
      var after: U8 = 0
      while true do
        before = _current(idx)?
        after = before + 1
        _current(idx)? = after
        if before < after then break end
        if idx == 0 then break
        else idx = idx - 1 end
      end
    end

  fun as_nonce(): String =>
    let clone = recover Array[U8](24) end
    for value in _current.values() do
      clone.push(value)
    end
    String.from_array(consume clone)

class iso _BoxStreamDecNonce is _InPlaceNonce
  var _current: Array[U8]
  new iso create(from: String) => _current = from.clone().iso_array()
  fun ref next() =>
    try
      var idx: USize = _current.size() - 1
      var before: U8 = 0
      var after: U8 = 0
      while true do
        before = _current(idx)?
        after = before + 1
        _current(idx)? = after
        if before < after then break end
        if idx == 0 then break
        else idx = idx - 1 end
      end
    end

  fun as_nonce(): String =>
    let clone = recover Array[U8](24) end
    for value in _current.values() do
      clone.push(value)
    end
    String.from_array(consume clone)

primitive DefaultNetworkId
  fun apply(): Array[U8] val =>
    [as U8: 0xd4; 0xa1; 0xcb; 0x88
            0xa6; 0x6f; 0x02; 0xf8
            0xdb; 0x63; 0x5c; 0xe2
            0x64; 0x41; 0xcc; 0x5d
            0xac; 0x1b; 0x08; 0x42
            0x0c; 0xea; 0xac; 0x23
            0x08; 0x39; 0xb7; 0x55
            0x84; 0x5a; 0x9f; 0xfb]

primitive _Handshake
  fun hello_challenge(pk: Curve25519Public, net_id: Array[U8] val): String? =>
    let auth = Sodium.auth_msg(pk.string(), net_id)?
    recover
      String.create(auth.size() + pk.size())
            .>append(auth)
            .>append(pk)
    end

  fun hello_verify(msg: String, net_id: Array[U8] val): Curve25519Public? =>
    if msg.size() != 64 then error end

    let other_hmac = msg.trim(0, 32)
    let other_eph_pk = msg.trim(32) // until the end

    let valid = Sodium.auth_msg_verify(
      where auth_tag = other_hmac,
      msg = other_eph_pk,
      key = net_id
    )

    if not valid then error end
    Curve25519Public(other_eph_pk.clone().iso_array())

  // Must be only called from server
  fun server_derive_secret_1(
    id_sk: Ed25519Secret,
    eph_sk: Curve25519Secret,
    other_eph_pk: Curve25519Public)
    : (_SharedSecret1, _SharedSecret2)?
  =>

    let short_term_ss = Sodium.scalar_mult(
      eph_sk.string(),
      other_eph_pk.string()
    )?

    let long_term_ss = Sodium.scalar_mult(
      Sodium.ed25519_sk_to_curve25519(id_sk)?.string(),
      other_eph_pk.string()
    )?

    (_SharedSecret1(short_term_ss), _SharedSecret2(long_term_ss))

  // Must be only called from client
  fun client_derive_secret_1(
    eph_sk: Curve25519Secret,
    other_eph_pk: Curve25519Public,
    other_id_pk: Ed25519Public)
    : (_SharedSecret1, _SharedSecret2)?
  =>

    let short_term_ss = Sodium.scalar_mult(
      eph_sk.string(),
      other_eph_pk.string()
    )?

    let long_term_ss = Sodium.scalar_mult(
      eph_sk.string(),
      Sodium.ed25519_pk_to_curve25519(other_id_pk)?.string()
    )?

    (_SharedSecret1(short_term_ss), _SharedSecret2(long_term_ss))

  fun client_detached_sign(
    server_pk: Ed25519Public,
    id_sk: Ed25519Secret,
    short_term_ss: _SharedSecret1,
    net_id: Array[U8] val)
    : _ClientDetachedSign?
  =>

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
    short_term_ss: _SharedSecret1,
    long_term_ss: _SharedSecret2,
    net_id: Array[U8] val)
    : String?
  =>

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
    short_term_ss: _SharedSecret1,
    long_term_ss: _SharedSecret2,
    net_id: Array[U8] val)
    : (_ClientDetachedSign, Ed25519Public)?
  =>

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

    let sign_detached = plain_text.trim(0, 64)
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

  fun client_derive_secret_2(id_sk: Ed25519Secret, other_eph_pk: Curve25519Public): _SharedSecret3? =>
    _SharedSecret3(Sodium.scalar_mult(
      Sodium.ed25519_sk_to_curve25519(id_sk)?.string(),
      other_eph_pk.string()
    )?)

  fun server_derive_secret_2(eph_sk: Curve25519Secret, other_id_pk: Ed25519Public): _SharedSecret3? =>
    _SharedSecret3(Sodium.scalar_mult(
      eph_sk.string(),
      Sodium.ed25519_pk_to_curve25519(other_id_pk)?.string()
    )?)

  fun server_detached_sign(
    server_id_sk: Ed25519Secret,
    client_id_pk: Ed25519Public,
    client_sign: _ClientDetachedSign,
    short_term_ss: _SharedSecret1,
    net_id: Array[U8] val)
    : _ServerDetachedSign?
  =>

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
    short_term_ss: _SharedSecret1,
    long_term_ss_1: _SharedSecret2,
    long_term_ss_2: _SharedSecret3,
    net_id: Array[U8] val)
    : String?
  =>

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
    short_term_ss: _SharedSecret1,
    long_term_ss_1: _SharedSecret2,
    long_term_ss_2: _SharedSecret3,
    net_id: Array[U8] val)
    : _ServerDetachedSign?
  =>

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
    ss_1: _SharedSecret1,
    ss_2: _SharedSecret2,
    ss_3: _SharedSecret3,
    net_id: Array[U8] val)
    : _BareBoxStreamSecret
  =>

    let msg_size = net_id.size() + ss_1.size() + ss_2.size() + ss_3.size()
    let msg = recover
      String.create(msg_size)
            .>append(String.from_array(net_id))
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
    other_eph_pk: Curve25519Public,
    net_id: Array[U8] val)
    : BoxStream^?
  =>

    let enc_k = String.from_array(SHA256(recover
      String.create(secret.size() + other_id_pk.size())
            .>append(secret.string())
            .>append(other_id_pk.string())
    end))

    let raw_enc_nonce = Sodium.auth_msg(other_eph_pk.string(), String.from_array(net_id))?.trim(0, 24)
    let enc_nonce = _BoxStreamEncNonce(raw_enc_nonce)

    let dec_k = String.from_array(SHA256(recover
      String.create(secret.size() + self_id_pk.size())
            .>append(secret.string())
            .>append(self_id_pk.string())
    end))

    let raw_dec_nonce = Sodium.auth_msg(self_eph_pk.string(), String.from_array(net_id))?.trim(0, 24)
    let dec_nonce = _BoxStreamDecNonce(raw_dec_nonce)

    BoxStream(_BoxStreamEncKey(enc_k), consume enc_nonce, _BoxStreamDecKey(dec_k), consume dec_nonce)

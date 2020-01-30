use "debug"
use "sodium"

class Handshake
  let _id_pk: Ed25519Public
  let _id_sk: Ed25519Secret

  let _eph_pk: Curve25519Public
  let _eph_sk: Curve25519Secret

  var _other_eph_pk: (Curve25519Public | None) = None

  var _short_term_shared_secret: (ByteSeq | None) = None
  var _long_term_shared_secret: (ByteSeq | None) = None

  let _network_id: Array[U8] val = [
    as U8: 0xd4; 0xa1; 0xcb; 0x88; 0xa6; 0x6f
           0x02; 0xf8; 0xdb; 0x63; 0x5c; 0xe2
           0x64; 0x41; 0xcc; 0x5d; 0xac; 0x1b
           0x08; 0x42; 0x0c; 0xea; 0xac; 0x23
           0x08; 0x39; 0xb7; 0x55; 0x84; 0x5a; 0x9f; 0xfb]

  new create(id_public: Ed25519Public,
             id_secret: Ed25519Secret,
             eph_public: Curve25519Public,
             eph_secret: Curve25519Secret) =>

    _id_pk = id_public
    _id_sk = id_secret
    _eph_pk = eph_public
    _eph_sk = eph_secret

  fun hello_challenge(): String? =>
    let auth = Sodium.auth_msg(_eph_pk.string(), _network_id)?
    recover String.create(auth.size() + _eph_pk.size()).>append(auth).>append(_eph_pk) end

  // TODO(borja): Should we store state inside this class?
  // Maybe it could lead to wrong usage, if, for example, a hello_verify returns
  // false, but we keep using it afterwards. As soon as the auth fails, we should
  // discard our ephemeral keys, and start from scratch.
  fun ref hello_verify(msg: String): Bool =>
    if msg.size() != 64 then false end

    let other_hmac = msg.trim(0, 31)
    let other_eph_pk = msg.trim(32) // until the end

    let valid = Sodium.auth_msg_verify(
      where auth_tag = other_hmac,
      msg = other_eph_pk,
      key = _network_id
    )

    if valid then
      _other_eph_pk = Curve25519Public(other_eph_pk.clone().iso_array())
    end

    valid

  // Must be only called from server
  fun ref server_derive_secret()? =>
    _short_term_shared_secret = Sodium.scalar_mult(
      _eph_sk.string(),
      (_other_eph_pk as Curve25519Public).string()
    )?

    _long_term_shared_secret = Sodium.scalar_mult(
      Sodium.ed25519_sk_to_curve25519(_id_sk)?.string(),
      (_other_eph_pk as Curve25519Public).string()
    )?

  // TODO(borja): Maybe SHS should already know other_id_pub?
  // Must be only called from client
  fun ref client_derive_secret(other_id_pub: Ed25519Public)? =>
    _short_term_shared_secret = Sodium.scalar_mult(
      _eph_sk.string(),
      (_other_eph_pk as Curve25519Public).string()
    )?

    _long_term_shared_secret = Sodium.scalar_mult(
      _eph_sk.string(),
      Sodium.ed25519_pk_to_curve25519(other_id_pub)?.string()
    )?

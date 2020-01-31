use "path:/usr/local/opt/libsodium/lib" if osx
use "lib:sodium"

use @sodium_init[I32]()
use @crypto_sign_publickeybytes[USize]()
use @crypto_sign_secretkeybytes[USize]()
// pk should be of size crypto_sign_publickeybytes
// sk should be of size crypto_sign_secretkeybytes
use @crypto_sign_keypair[I32](pk: Pointer[U8] tag, sk: Pointer[U8] tag)
// pk is filled by callee
use @crypto_sign_ed25519_sk_to_pk[I32](pk: Pointer[U8] tag, sk: Pointer[U8] tag)

// Ephemeral Curve25519
use @crypto_box_publickeybytes[USize]()
use @crypto_box_secretkeybytes[USize]()
use @crypto_box_keypair[I32](pk: Pointer[U8] tag, sk: Pointer[U8] tag)

use @crypto_auth_bytes[USize]()
use @crypto_auth_keybytes[USize]()
// Sign the msg in `in_buf` of size `inlen` with key `k` (of size crypto_auth_keybytes)
use @crypto_auth[I32](out: Pointer[U8] tag,
                      in_buf: Pointer[U8] tag,
                      inlen: ULong,
                      k: Pointer[U8] tag)

// Verify that `h` is a valid tag for msg signed with k
use @crypto_auth_verify[I32](h: Pointer[U8] tag,
                             msg: Pointer[U8] tag,
                             inlen: ULong,
                             k: Pointer[U8] tag)


use @crypto_scalarmult_bytes[USize]()
// Multiply `p` by a scalar `n` and put the result in `q`
// `q` should be of size crypto_scalarmult_bytes
use @crypto_scalarmult[I32](q: Pointer[U8] tag, n: Pointer[U8] tag, p: Pointer[U8] tag)

use @crypto_scalarmult_curve25519_bytes[USize]()
// Convert a Ed25519 pk into X25519 pk, or
// convert a Ed25519 sk into X25519 sk
// The X25519 keys must be of size crypto_scalarmult_curve25519_bytes
use @crypto_sign_ed25519_pk_to_curve25519[I32](curve: Pointer[U8] tag, pk: Pointer[U8] tag)
use @crypto_sign_ed25519_sk_to_curve25519[I32](curve: Pointer[U8] tag, sk: Pointer[U8] tag)

use @crypto_sign_bytes[USize]()
// Sign message `m` (of size `mlen`) with `sk`. The result will be written to `sig`, and its
// size will be written to `siglen`. `siglen` will be up to crypto_sign_bytes.
use @crypto_sign_detached[I32](sig: Pointer[U8] tag, siglen: Pointer[ULong] ref,
                               m: Pointer[U8] tag, mlen: ULong,
                               sk: Pointer[U8] tag)

// Verify a signature crafted with crypto_sign_detached
use @crypto_sign_verify_detached[I32](sig: Pointer[U8] tag,
                                      m: Pointer[U8] tag, mlen: ULong,
                                      pk: Pointer[U8] tag)

use @crypto_secretbox_macbytes[USize]()
use @crypto_secretbox_keybytes[USize]()
use @crypto_secretbox_noncebytes[USize]()
// Encrypt message `m` (of size `mlen`) with key `k`, and put it into `c`.
// `c` should be of at least crypto_secretbox_macbytes + `mlen`
// `key` should be of size crypto_secretbox_keybytes
// `nonce` should be of size crypto_secretbox_noncebytes
use @crypto_secretbox_easy[I32](c: Pointer[U8] tag,
                                m: Pointer[U8] tag, mlen: ULong,
                                nonce: Pointer[U8] tag,
                                key: Pointer[U8] tag)

// Decrypt a message encrypted with crypto_secretbox_easy
// `c` is the cyphertext, of size `clen`
// `nonce` and `key` have to match the used in crypto_secretbox_easy
use @crypto_secretbox_open_easy[I32](m: Pointer[U8] tag,
                                     c: Pointer[U8] tag, clen: ULong,
                                     nonce: Pointer[U8] tag,
                                     key: Pointer[U8] tag)

// TODO(borja): Consider changing impl to a String, easier to use
interface val _OpaqueBuffer
  fun _get_inner(): Array[U8] val
  fun apply(i: USize): U8? => _get_inner()(i)?
  fun values(): Iterator[U8] ref^ => _get_inner().values()
  fun cpointer(): Pointer[U8] tag => _get_inner().cpointer()
  fun size(): USize => _get_inner().size()
  fun string(): String => String.from_array(_get_inner())

class val Ed25519Public is _OpaqueBuffer
  let _inner: Array[U8] val
  new val create(from: Array[U8] iso) => _inner = consume from
  new val from_string(from: String) => _inner = from.array()
  fun _get_inner(): Array[U8] val => _inner

class val Ed25519Secret is _OpaqueBuffer
  let _inner: Array[U8] val
  new val create(from: Array[U8] iso) => _inner = consume from
  fun _get_inner(): Array[U8] val => _inner

class val Curve25519Public is _OpaqueBuffer
  let _inner: Array[U8] val
  new val create(from: Array[U8] iso) => _inner = consume from
  fun _get_inner(): Array[U8] val => _inner

class val Curve25519Secret is _OpaqueBuffer
  let _inner: Array[U8] val
  new val create(from: Array[U8] iso) => _inner = consume from
  fun _get_inner(): Array[U8] val => _inner

primitive Sodium
  fun _make_buffer(len: USize): Array[U8] iso^ =>
    recover
      Array[U8].from_cpointer(
        @pony_alloc[Pointer[U8]](@pony_ctx[Pointer[None] iso](), len),
        len
        )
    end

  fun init()? =>
    if \unlikely\ @sodium_init() == -1 then
      error
    end

  fun ed25519_pair(): (Ed25519Public, Ed25519Secret)? =>
    let pk = _make_buffer(@crypto_sign_publickeybytes())
    let sk = _make_buffer(@crypto_sign_secretkeybytes())

    let ret = @crypto_sign_keypair(pk.cpointer(), sk.cpointer())
    if \unlikely\ ret != 0 then error end

    (Ed25519Public(consume pk), Ed25519Secret(consume sk))

  fun ed25519_pair_sk_to_pk(sk: Ed25519Secret): Ed25519Public? =>
    let pk = _make_buffer(@crypto_sign_publickeybytes())
    let ret = @crypto_sign_ed25519_sk_to_pk(pk.cpointer(), sk.cpointer())
    if \unlikely\ ret != 0 then error end
    Ed25519Public(consume pk)

  fun curve25519_pair(): (Curve25519Public, Curve25519Secret)? =>
    let pk = _make_buffer(@crypto_box_publickeybytes())
    let sk = _make_buffer(@crypto_box_secretkeybytes())

    let ret = @crypto_box_keypair(pk.cpointer(), sk.cpointer())
    if \unlikely\ ret != 0 then error end

    (Curve25519Public(consume pk), Curve25519Secret(consume sk))

  fun auth_msg(msg: ByteSeq, key: ByteSeq): String? =>
    if key.size() != @crypto_auth_keybytes() then
      error
    end

    let resp = _make_buffer(@crypto_auth_bytes())
    let ret = @crypto_auth(resp.cpointer(), msg.cpointer(), msg.size().ulong(), key.cpointer())
    if \unlikely\ ret != 0 then error end

    String.from_array(consume resp)

  fun auth_msg_verify(auth_tag: ByteSeq, msg: ByteSeq, key: ByteSeq): Bool =>
    0 == @crypto_auth_verify(auth_tag.cpointer(),
                             msg.cpointer(),
                             msg.size().ulong(),
                             key.cpointer())

  fun scalar_mult(scalar: ByteSeq, point: ByteSeq): String? =>
    let q = _make_buffer(@crypto_scalarmult_bytes())
    let ret = @crypto_scalarmult(q.cpointer(), scalar.cpointer(), point.cpointer())
    if \unlikely\ ret != 0 then error end

    String.from_array(consume q)

  fun ed25519_pk_to_curve25519(pk: Ed25519Public): Curve25519Public? =>
    let curve_pk = _make_buffer(@crypto_scalarmult_curve25519_bytes())
    let ret = @crypto_sign_ed25519_pk_to_curve25519(curve_pk.cpointer(), pk.cpointer())
    if \unlikely\ ret != 0 then error end

    Curve25519Public(consume curve_pk)

  fun ed25519_sk_to_curve25519(sk: Ed25519Secret): Curve25519Secret? =>
    let curve_sk = _make_buffer(@crypto_scalarmult_curve25519_bytes())
    let ret = @crypto_sign_ed25519_sk_to_curve25519(curve_sk.cpointer(), sk.cpointer())
    if \unlikely\ ret != 0 then error end

    Curve25519Secret(consume curve_sk)

  fun sign_detached(msg: ByteSeq, key: ByteSeq): (String, ULong)? =>
    let signature = _make_buffer(@crypto_sign_bytes())
    var signature_len = ULong(0)
    let ret = @crypto_sign_detached(
      signature.cpointer(),
      addressof signature_len,
      msg.cpointer(),
      msg.size().ulong(),
      key.cpointer()
    )

    if \unlikely\ ret != 0 then error end

    (String.from_array(consume signature), signature_len)

  fun sign_detached_verify(sig: ByteSeq, msg: ByteSeq, key: ByteSeq): Bool =>
    0 == @crypto_sign_verify_detached(sig.cpointer(),
                                      msg.cpointer(),
                                      msg.size().ulong(),
                                      key.cpointer())

  fun box_easy(msg: ByteSeq, key: ByteSeq, nonce: ByteSeq): String? =>
    if key.size() != @crypto_secretbox_keybytes() then
      error
    end

    if nonce.size() != @crypto_secretbox_noncebytes() then
      error
    end

    let enc = _make_buffer(@crypto_secretbox_macbytes() + msg.size())
    let ret = @crypto_secretbox_easy(enc.cpointer(),
                                     msg.cpointer(), msg.size().ulong(),
                                     nonce.cpointer(),
                                     key.cpointer())

    if \unlikely\ ret != 0 then error end
    String.from_array(consume enc)

  fun box_easy_open(enc: ByteSeq, key: ByteSeq, nonce: ByteSeq): String? =>
    if key.size() != @crypto_secretbox_keybytes() then
      error
    end

    if nonce.size() != @crypto_secretbox_noncebytes() then
      error
    end

    if enc.size() < @crypto_secretbox_macbytes() then
      error // Msg doesn't contain anything
    end

    // Use -? just in case we underflow, although we checked beforehand
    let msg = _make_buffer(enc.size() -? @crypto_secretbox_macbytes())
    let ret = @crypto_secretbox_open_easy(msg.cpointer(),
                                          enc.cpointer(), enc.size().ulong(),
                                          nonce.cpointer(),
                                          key.cpointer())
    if \unlikely\ ret != 0 then error end
    String.from_array(consume msg)

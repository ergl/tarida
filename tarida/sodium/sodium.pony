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

class val Ed25519Public
  let _inner: Array[U8] val
  new val create(from: Array[U8] iso) => _inner = consume from
  fun apply(i: USize): U8? => _inner(i)?
  fun values(): Iterator[U8] ref^ => _inner.values()
  fun cpointer(): Pointer[U8] tag => _inner.cpointer()
  fun size(): USize => _inner.size()
  fun string(): String => String.from_array(_inner)

class val Ed25519Secret
  let _inner: Array[U8] val
  new val create(from: Array[U8] iso) => _inner = consume from
  fun apply(i: USize): U8? => _inner(i)?
  fun values(): Iterator[U8] ref^ => _inner.values()
  fun cpointer(): Pointer[U8] tag => _inner.cpointer()
  fun size(): USize => _inner.size()
  fun string(): String => String.from_array(_inner)

class val Curve25519Public
  let _inner: Array[U8] val
  new val create(from: Array[U8] iso) => _inner = consume from
  fun apply(i: USize): U8? => _inner(i)?
  fun values(): Iterator[U8] ref^ => _inner.values()
  fun cpointer(): Pointer[U8] tag => _inner.cpointer()
  fun size(): USize => _inner.size()
  fun string(): String => String.from_array(_inner)

class val Curve25519Secret
  let _inner: Array[U8] val
  new val create(from: Array[U8] iso) => _inner = consume from
  fun apply(i: USize): U8? => _inner(i)?
  fun values(): Iterator[U8] ref^ => _inner.values()
  fun cpointer(): Pointer[U8] tag => _inner.cpointer()
  fun size(): USize => _inner.size()
  fun string(): String => String.from_array(_inner)

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

  fun auth_msg(msg: ByteSeq, key: ByteSeq): ByteSeq? =>
    if key.size() != @crypto_auth_keybytes() then
      error
    end

    let resp = _make_buffer(@crypto_auth_bytes())
    let ret = @crypto_auth(resp.cpointer(), msg.cpointer(), msg.size().ulong(), key.cpointer())
    if \unlikely\ ret != 0 then error end

    resp

  fun auth_msg_verify(auth_tag: ByteSeq, msg: ByteSeq, key: ByteSeq): Bool =>
    0 == @crypto_auth_verify(auth_tag.cpointer(),
                             msg.cpointer(),
                             msg.size().ulong(),
                             key.cpointer())

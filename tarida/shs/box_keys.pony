// TODO(borja): BoxKeys.apply() returns a BoxStream
// BoxStream will encrypt and decrypt messages you give it, and automatically
// increment or update the nonces as it goes.
// This way it can be used from a TCPConnectionNotify to transparently
// encrypt/decrypt messages in both ways
//
// By having a private type as its only argument, we can make sure that only
// this package can craft a correct BoxStream object
// Another option would be to use capabilites a la AmbientAuth, etc
//
// A server needs a pair of box streams: one for sending and another for
// receiving messages (no duplex). So one box stream only knows how to decrypting,
// and the only one only needs to know about encrypting.

use "package:../sodium"

class iso BoxStream
  let _enc_key: _BoxStreamEncKey
  let _dec_key: _BoxStreamDecKey

  let _enc_nonce: _BoxStreamEncNonce
  let _dec_nonce: _BoxStreamDecNonce

  new iso create(
    enc_key: _BoxStreamEncKey,
    enc_nonce: _BoxStreamEncNonce,
    dec_key: _BoxStreamDecKey,
    dec_nonce: _BoxStreamDecNonce)
  =>
    _enc_key = enc_key
    _enc_nonce = consume enc_nonce

    _dec_key = dec_key
     _dec_nonce = consume dec_nonce

  fun header_size(): USize => 34

  fun ref encrypt(msg: String): String? =>
    let msg_size = msg.size()
    // TODO(borja): Perform chunking at a higher level
    if msg_size > 4096 then error end

    let header_nonce = _enc_nonce.as_nonce(); _enc_nonce.next()
    let body_nonce = _enc_nonce.as_nonce(); _enc_nonce.next()

    let packet_size = msg_size + 34
    let packet = recover String.create(packet_size) end

    let raw_enc_body = Sodium.box_easy(msg, _enc_key.string(), body_nonce)?
    let auth_tag = raw_enc_body.trim(0, 16)
    let enc_body = raw_enc_body.trim(16)
    let header = recover [as U8: (msg_size >> 8).u8(); msg_size.u8()].>append(auth_tag) end
    let enc_header = Sodium.box_easy(consume header, _enc_key.string(), header_nonce)?

    packet.>append(enc_header).>append(enc_body)

  fun ref decrypt_header(msg: String): ((USize, String) | None)? =>
    let header_nonce = _dec_nonce.as_nonce(); _dec_nonce.next()
    let header = recover val Sodium.box_easy_open(msg, _dec_key.string(), header_nonce)? end
    if header.size() != 18 then error end // Spec
    // If this msg is a goodbye, the caller should close the connection
    if _is_goodbye(header) then return None end
    let raw_body_size = header.trim(0, 2) // First two bytes are the body size
    // Convert back to USize
    let body_size = (raw_body_size(0)?.usize() << 8) + (raw_body_size(1)?.usize())
    let body_auth = header.trim(2)

    (body_size, body_auth)

  fun _is_goodbye(body_auth: String): Bool =>
    for bytes in body_auth.values() do
      if bytes != U8(0) then return false end
    end
    true

  fun ref decrypt(body_auth: String, msg: String): String iso^? =>
    let body_nonce = _dec_nonce.as_nonce(); _dec_nonce.next()

    let msg_size = msg.size() + body_auth.size() // Auth should be 16 bytes
    let enc_msg = recover String.create(msg_size).>append(body_auth).>append(msg) end
    Sodium.box_easy_open(consume enc_msg, _dec_key.string(), body_nonce)?

  fun ref keys(): Array[U8] val =>
    // FIXME(borja): Add `ifdef debug then` later
    let enc_nonce = _enc_nonce.as_nonce().array()
    let dec_nonce = _dec_nonce.as_nonce().array()

    let size = _enc_key.size() + enc_nonce.size() +
                _dec_key.size() + dec_nonce.size()

    let arr = recover Array[U8].create(size) end
    arr.append(_enc_key.string().array())
    arr.append(enc_nonce)
    arr.append(_dec_key.string().array())
    arr.append(dec_nonce)
    consume arr

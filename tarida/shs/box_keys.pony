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

// Nonces are incremented by one on every message, so we need to be able to
// update them in-place for efficiency. When passed to Sodium though, they'll
// need to be immutable. So we need to find a way to make this possible without
// having a lot of copies (returning an iso that can be consumed?)
// TODO(borja): Figure out if we need to keep into account that we might
// reuse nonces. Should we crash?
interface iso _InPlaceNonce
  fun ref _get_inner(): Array[U8]
  fun ref next() =>
    let inner = _get_inner()
    try
      var idx = inner.size() - 1
      var n = U8(0)
      var prev = U8(0)
      while idx >= 0 do
        prev = inner(idx)?
        n = (prev + 1).mod(10)
        inner(idx)? = n
        if prev < n then
          break
        end
        idx = idx - 1
      end
    else
      None
    end

class iso _InPlaceEncNonce is _InPlaceNonce
  let _inner: Array[U8]
  new create(from: _BoxStreamEncNonce) =>
    // FIXME(borja): Ugh, make this better
    _inner = from._get_inner().clone().iso_array()
  fun ref _get_inner(): Array[U8] => _inner

class iso BoxStream
  let _original_enc_nonce: _BoxStreamEncNonce
  let _original_dec_nonce: _BoxStreamDecNonce

  let _enc_key: _BoxStreamEncKey
  let _dec_key: _BoxStreamDecKey

  var _enc_nonce: _BoxStreamEncNonce
  var _dec_nonce: _BoxStreamDecNonce

  new iso create(keys: _BoxKeys) =>
    _enc_key = keys._1
     _enc_nonce = keys._2
     _original_enc_nonce = _enc_nonce

    _dec_key = keys._3
     _dec_nonce = keys._4
     _original_dec_nonce = _dec_nonce

  fun header_size(): USize => 34

  fun ref encrypt(msg: String): String? =>
    // TODO(borja): Perform chunking at a higher level
    if msg.size() > 4096 then error end
    // TODO(borja): Implement
    msg

primitive BoxKeys
  fun apply(shs: (HandshakeServer | HandshakeClient)): BoxStream iso^? =>
    BoxStream(shs._full_secret()?)
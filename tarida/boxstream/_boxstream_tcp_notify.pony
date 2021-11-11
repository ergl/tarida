use "../shs"
use "../sodium"

use "logger"
use "net"

primitive _BoxStreamExpectHeader
class val _BoxStreamExpectBody
  let auth_tag: String
  new val create(other_tag: String) =>
    auth_tag = other_tag

type _BoxStreamTCPNotifyState is (_BoxStreamExpectHeader | _BoxStreamExpectBody)
class _BoxStreamTCPNotify is TCPConnectionNotify
  let _logger: Logger[String val]
  var _notify: BoxStreamNotify ref
  var _notify_called: USize = 0

  let _boxstream: BoxStream
  var _state: _BoxStreamTCPNotifyState

  new iso _create(
    logger: Logger[String] val,
    notify: BoxStreamNotify,
    boxtream: BoxStream iso,
    conn: TCPConnection,
    peer_pk: Ed25519Public)
  =>
    _logger = logger
    _notify = consume ref notify

    _boxstream = consume boxtream
    _state = _BoxStreamExpectHeader

    _notify.connected_to(conn, peer_pk)

  fun ref connect_failed(conn: TCPConnection ref) =>
    _notify.connect_failed(conn)

  fun ref sent(conn: TCPConnection ref, data: ByteSeq): ByteSeq =>
    // The client only calls write if the data fits into a single chunk
    try
      _boxstream.encrypt(data)?
    else
      _logger(Error) and _logger.log(
        "Error while encrypting write, drop it like it's hot"
      )
      ""
    end

  fun ref sentv(conn: TCPConnection ref, data: ByteSeqIter): ByteSeqIter =>
    // Since we get a val, we can't modify the data in place
    // But, we're only allocating a few chunks, so hopefully it's not too bad
    let io_vecs = recover Array[ByteSeq] end
    for chunk in data.values() do
      try
        io_vecs.push(_boxstream.encrypt(chunk)?)
      else
        _logger(Error) and _logger.log(
          "Error while encrypting chunk: drop it like it's hot"
        )
      end
    end

    io_vecs

  fun ref received(
    conn: TCPConnection ref,
    data: Array[U8] iso,
    times: USize)
    : Bool
  =>
    let msg = String.from_array(consume data)
    try
      match _state
      | _BoxStreamExpectHeader =>
        let result = _boxstream.decrypt_header(consume msg)?
        match result
        | None => conn.close() // goodbye

        | (let next_expect: USize, let auth_tag: String) =>
            conn.expect(next_expect)?
            _state = _BoxStreamExpectBody(auth_tag)
        end

      | let info: _BoxStreamExpectBody =>
        let decrypted = _boxstream.decrypt(info.auth_tag, msg)?.iso_array()
        _notify.received(conn, consume decrypted, _notify_called)
        _notify_called = _notify_called + 1
        conn.expect(_boxstream.header_size())?
        _state = _BoxStreamExpectHeader
      end

      true
    else
      conn.close()
      _logger(Error) and _logger.log("Bad boxstream receive")
      false
    end

  fun ref closed(conn: TCPConnection ref) =>
    // TODO(borja): Should we send the goodbye here?
    _notify.closed(conn)


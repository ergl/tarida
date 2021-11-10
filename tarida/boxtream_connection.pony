use "shs"
use "sodium"
use "identity"

use "net"
use "debug"

primitive _BoxStreamExpectHeader
class val _BoxStreamExpectBody
  let auth_tag: String
  new val create(other_tag: String) =>
    auth_tag = other_tag

type _BoxStreamNotifyState is (_BoxStreamExpectHeader | _BoxStreamExpectBody)
class _BoxStreamNotify is TCPConnectionNotify
  let _socket: TCPConnection

  let _notify: RPCConnectionServer

  let _boxstream: BoxStream
  var _state: _BoxStreamNotifyState

  new iso create(
    socket: TCPConnection,
    self_pk: Ed25519Public,
    self_sk: Ed25519Secret,
    remote_pk: Ed25519Public,
    boxtream: BoxStream iso)
  =>
    _boxstream = consume boxtream
    _state = _BoxStreamExpectHeader

    _socket = socket
    Debug.out("_BoxStreamNotify: connected to: " + Identity.cypherlink(remote_pk))
    _notify = RPCConnectionServer(_socket, self_pk, self_sk, remote_pk)

  fun ref connect_failed(conn: TCPConnection ref) => None

  fun ref sent(conn: TCPConnection ref, data: ByteSeq): ByteSeq =>
    // The client only calls write if the data fits into a single chunk
    try
      _boxstream.encrypt(data)?
    else
      Debug.err("_BoxStreamNotify: error while encrypting write, drop it like it's hot")
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
        Debug.err("_BoxStreamNotify: error while encrypting chunk, drop it like it's hot")
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
        _notify._chunk(_boxstream.decrypt(info.auth_tag, msg)?.iso_array())
        conn.expect(_boxstream.header_size())?
        _state = _BoxStreamExpectHeader
      end

      true
    else
      conn.close()
      Debug.err("Error: _BoxStreamNotify bad recv")
      false
    end

  fun ref closed(conn: TCPConnection ref) =>
    // TODO(borja): Should we send the goodbye here?
    None

use "net"
use "shs"
use "sodium"
use "debug"

// SHS/RPC Ideas:
// On starting, our TCP server uses a Handshake notify, that performs the SHS mechanism.
// When/if the handshake succeeds, it changes the notify: the new one is a nested notify.
// The outter layer performs the box stream framing and enc/decryption.
// The next layer is the RPC mechanism, which also handles framing.
// The RPC layer can either be the final layer, or delegate RPC header parsing to another notifier.

type RPCMessage is (U8, I32, ByteSeq)

class MessageSlicer
  var _buffer: Array[U8] iso

  new create(size': USize = 0) =>
    _buffer = recover Array[U8].create(size') end

  fun ref append(bytes: ByteSeq) =>
    _buffer.append(consume bytes)

  fun ref decode_msg(): (RPCMessage | None)? =>
    let header_size: USize = 9
    let data_size = _buffer.size()

    if data_size < header_size then
      return None
    end

    let body_size = _buffer_read_u32_be(1)?.usize()
    let total_size = header_size + body_size
    if data_size < total_size then
      return None
    end

    let flags = _buffer(0)?
    let req_number = _buffer_read_u32_be(5)?.i32()

    _buffer.trim_in_place(header_size)
    (let message_body, _buffer) = (consume _buffer).chop(body_size)

    (flags, req_number, consume message_body)

  fun ref _buffer_read_u32_be(offset: USize): U32? =>
    ifdef bigendian then
      _buffer.read_u32(offset)?
    else
      _buffer.read_u32(offset)?.bswap()
    end

  fun ref size(): USize =>
    _buffer.size()

actor RPCConnection
  let _socket: TCPConnection
  embed _buffer: MessageSlicer

  new create(raw_socket: TCPConnection) =>
    _socket = raw_socket
    _buffer = MessageSlicer

  be write(data: ByteSeq) =>
    _socket.write(consume data)

  be chunk(data: (String iso | Array[U8] iso)) =>
    Debug.out("Have left in buffer: " + _buffer.size().string())
    _buffer.append(consume data)
    _try_deliver_chunks()

  fun ref _try_get_all_msgs(): Array[RPCMessage] iso^ =>
    let msgs = recover Array[RPCMessage] end
    while true do
      try
        match _buffer.decode_msg()?
        | None =>
          Debug.out("RPCConnection can't find entire msg")
          break
        | let msg: RPCMessage => msgs.push(msg)
        end
      else
        Debug.err("RPCConnection: _decode_packet bad packet")
        break
      end
    end
    consume msgs

  fun ref _try_deliver_chunks() =>
    let ready_msgs = _try_get_all_msgs()
    for msg in (consume ready_msgs).values() do
      (_, let packet_number, let body) = msg
      let body_msg = match body
      | let a: Array[U8] val => String.from_array(a)
      | let s: String => s
      end

      Debug.out("Got RPC message number " + packet_number.string() + ": " + body_msg)
    end

primitive _BoxStreamExpectHeader
class val _BoxStreamExpectBody
  let auth_tag: String
  new val create(other_tag: String) =>
    auth_tag = other_tag

type _BoxStreamNotifyState is (_BoxStreamExpectHeader | _BoxStreamExpectBody)

class _BoxStreamNotify is TCPConnectionNotify
  let _socket: TCPConnection

  let _notify: RPCConnection

  let _boxstream: BoxStream
  var _state: _BoxStreamNotifyState

  new create(socket: TCPConnection, boxtream: BoxStream iso) =>
    _boxstream = consume boxtream
    _state = _BoxStreamExpectHeader

    _socket = socket
    _notify = RPCConnection(_socket)

  fun ref connect_failed(conn: TCPConnection ref) => None

  fun ref sent(conn: TCPConnection ref, data: ByteSeq): ByteSeq =>
    // TODO(borja): Encrypt data here. Must return the transformed data
    // Remember the 4096 byte limit
    data

  fun ref sentv(conn: TCPConnection ref, data: ByteSeqIter): ByteSeqIter =>
    // TODO(borja): Encrypt data here. Will this be used?
    // Remember the 4096 byte limit per byteseq
    data

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
        Debug.out("_BoxStreamNotify recv header of size " + msg.size().string())
        let result = _boxstream.decrypt_header(consume msg)?
        match result
        | None => // goodbye
          Debug.out("Recv a goodbye")
          conn.close()

        | (let next_expect: USize, let auth_tag: String) =>
            conn.expect(next_expect)?
            _state = _BoxStreamExpectBody(auth_tag)
        end

      | let info: _BoxStreamExpectBody =>
        Debug.out("_BoxStreamNotify recv body of size " + msg.size().string())

        _notify.chunk(_boxstream.decrypt(info.auth_tag, msg)?.iso_array())
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

class iso _PeerNotify is TCPConnectionNotify
  let _shs: HandshakeServer
  new iso create(h: HandshakeServer) =>
    _shs = consume h

  fun ref accepted(conn: TCPConnection ref) =>
    // Create ephemeral keys on connection
    try conn.expect(_shs.init()?)? else conn.close() end

  fun ref received(
    conn: TCPConnection ref,
    data: Array[U8] iso,
    times: USize)
    : Bool
  =>
    let msg = String.from_iso_array(consume data)
    try
      (let expect, let resp) = _shs.step(consume msg)?
      if expect == 0 then
        Debug.out("Handshake complete")
        let boxstream = _shs.boxstream()?
        conn.expect(boxstream.header_size())?
        let conn_tag = recover tag conn end
        conn.set_notify(recover _BoxStreamNotify(conn_tag, consume boxstream) end)
      else
        conn.expect(expect)?
      end

      conn.write_final(resp)
    else
      Debug.err("Error: _PeerNotify bad SHS")
      conn.close()
    end

    true

  fun ref closed(conn: TCPConnection ref) =>
    Debug.out("_PeerNotify closed")

  fun ref connect_failed(conn: TCPConnection ref) =>
    None

class iso _PeerListenNotify is TCPListenNotify
  let _pk: Ed25519Public
  let _sk: Ed25519Secret

  new iso create(pk: Ed25519Public, sk: Ed25519Secret) =>
    (_pk, _sk) = (pk, sk)

  fun ref listening(listen: TCPListener ref) =>
    try
      (let addr, let port) = listen.local_address().name()?
      Debug.out("_PeerListenNotify listening on " + addr + ":" + port)
    end

  fun ref connected(
    listen: TCPListener ref)
    : TCPConnectionNotify iso^
  =>
    Debug.out("_PeerListenNotify connected")
    _PeerNotify(HandshakeServer(_pk, _sk, DefaultNetworkId()))

  fun ref not_listening(listen: TCPListener ref) =>
    Debug.err("_PeerListenNotify not_listening")
    None

actor PeerServer
  new create(
    auth: NetAuth,
    pk: Ed25519Public,
    sk: Ed25519Secret,
    port: String)
  =>
    TCPListener(
      auth,
      _PeerListenNotify(pk, sk),
      "",
      port)

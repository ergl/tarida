use "net"
use "shs"
use "sodium"
use "debug"
use "rpc"
use "handlers"
use "collections"
use "promises"

// SHS/RPC Ideas:
// On starting, our TCP server uses a Handshake notify, that performs the SHS mechanism.
// When/if the handshake succeeds, it changes the notify: the new one is a nested notify.
// The outter layer performs the box stream framing and enc/decryption.
// The next layer is the RPC mechanism, which also handles framing.
// The RPC layer can either be the final layer, or delegate RPC header parsing to another notifier.

actor RPCConnection
  let _socket: TCPConnection
  let _remote_pk: Ed25519Public
  // A mapping of sequence number to handler on that stream
  embed _active_handlers: Map[U32, Handler]
  embed _buffer: RPCDecoder

  new create(raw_socket: TCPConnection, other_pk: Ed25519Public) =>
    _socket = raw_socket
    _remote_pk = other_pk
    _active_handlers = Map[U32, Handler]
    _buffer = RPCDecoder

  be write(msg: RPCMsg iso) =>
    var bytes = RPCEncoder(consume msg)

    // If we perform chunking at a lower layer,
    // we'll end up coping a lot of things, since they get a `val` view
    let chunk_size: USize = 4096
    let chunks = (bytes.size().f64() / chunk_size.f64()).ceil().usize()
    let io_vecs = recover Array[Array[U8] val].create(chunks) end
    while true do
      if chunk_size > bytes.size() then
        // Push remainder, and exit
        // (destructive read to get over "bytes is consumed at the end of loop")
        // Take into leftover all what's left of bytes, and assign an empty byteseq
        let leftover = bytes = recover [] end
        // _socket.write(consume leftover)
        io_vecs.push(consume leftover)
        break
      else
        (bytes, let current_chunk) = (consume bytes).chop(chunk_size)
        // _socket.write(consume current_chunk)
        io_vecs.push(consume current_chunk)
      end
    end

    _socket.writev(consume io_vecs)

  fun tag remote_pk(): Promise[Ed25519Public] =>
    let p = Promise[Ed25519Public]
    _fetch_remote_pk(p)
    p

  be _fetch_remote_pk(promise: Promise[Ed25519Public]) =>
    promise(_remote_pk)?

  be _chunk(data: (String iso | Array[U8] iso)) =>
    Debug.out("Have left in buffer: " + _buffer.size().string())
    _buffer.append(consume data)
    _try_process_chunks()

  fun ref _try_process_chunks() =>
    while true do
      try
        match _buffer.decode_msg()?
        | None => break
        | Goodbye =>
          Debug.out("RPCConnection: goodbye")
          // The client is going away, clean up all resources
          _cleanup_handlers()
          _socket.dispose()
          break
        | let msg: RPCMsg iso => _process_msg(consume msg)
        end
      else
        Debug.err("RPCConnection: _decode_packet bad packet")
        break
      end
    end

  fun ref _cleanup_handlers() =>
    for h in _active_handlers.values() do
      h.handle_disconnect(this)
    end
    _active_handlers.clear()

  // TODO(borja): If the message is of kind end/err, we should clean up the handler
  fun ref _process_msg(msg: RPCMsg iso) =>
    let seq = msg.header().packet_number
    // We take the absolute value of seq, since replies are in negative
    let h_key = seq.abs()
    if _active_handlers.contains(h_key) then
      try
        let handler_for_msg = _active_handlers(h_key)?
        handler_for_msg.handle_call(this, consume msg)
      end

      return
    end

    // From now on, we know there's no handler for this message _yet_

    // If the original seq was a reply, and we don't have a handler,
    // simply drop the message on the floor
    if seq < 0 then
      Debug.err(
        "RPCConnection: got reply to nonexistant handler at seq " + h_key.string()
      )

      return
    end

    // To be able to handle a message, we have to know how. Right now, the
    // only way to do that is to inspect the namespace of a json method.
    // So, the message _must_ be json. If it isn't, drop it on the floor.
    if msg.header().type_info isnt JSONMessage then
      Debug.err("RPCConnection: can't handle msg " + msg.string())
      return
    end

    // The message also has to be a valid method. Again, drop it on the floor
    // if it isn't (it's not a method if it doesn't have a namespace)
    // TODO(borja): Look if there's a case where we get a legitimate non-json
    // message without an already active handler.
    let namespace = msg.namespace()
    if namespace is None then
      Debug.err("RPCConnection: bad json method " + msg.string())
      return
    end

    // TODO(borja): Consider the performance of this
    // Right now, we're spawning a new actor everytime we encounter a new
    // message stream (from a sequence number we haven't seen yet, and with
    // a json body with a namespace we know how to handle). This could cause
    // a DOS if a client spawns multiple messages of the same type but with
    // different sequence numbers.
    //
    // Another issue is that spawning an entire actor might be wasteful.
    // For messages that are not source (i.e. async/sync), it's better
    // to have a long-running actor to handle those messages.
    //
    // Perhaps, if we encounter a message of type async/sync for the first
    // time, spawn an actor, and don't despawn it: keep reusing it for the
    // same message type, even if the sequence number is not the same.
    try
      let namespace_str = namespace as String // Can't error, we already know
      match HandlerRegistrar(namespace_str)
      | None =>
          Debug.err(
           "RPCConnection: don't know how to handle "
           + namespace_str
           + " messages. Got msg: "
           + msg.string()
          )

      | let h: Handler =>
            h.handle_call(this, consume msg)
            _active_handlers(h_key) = h
      end
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

  new create(
    socket: TCPConnection,
    remote_pk: Ed25519Public,
    boxtream: BoxStream iso)
  =>
    _boxstream = consume boxtream
    _state = _BoxStreamExpectHeader

    _socket = socket
    _notify = RPCConnection(_socket, remote_pk)

  fun ref connect_failed(conn: TCPConnection ref) => None

  fun ref sent(conn: TCPConnection ref, data: ByteSeq): ByteSeq =>
    // TODO(borja): Encrypt data here. Will this be used?
    // Remember the 4096 byte limit per byteseq
    Debug.err("sending single byte seq will be dropped")
    ""

  fun ref sentv(conn: TCPConnection ref, data: ByteSeqIter): ByteSeqIter =>
    // The upper layer already perfomed chunking, so we're safe
    // TODO(borja): Encrypt data here. Will this be used?
    // Remember the 4096 byte limit per byteseq
    // Since we get a val, we can't modify the data in place
    // But, we're only allocating a few chunks, so hopefully it's not too bad
    let io_vecs = recover Array[ByteSeq] end
    for chunk in data.values() do
      try
        io_vecs.push(_boxstream.encrypt(chunk)?)
      else
        Debug.err("_BoxStreamNotify: error while encrypting chunk")
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
        let remote_pk = _shs.remote_pk()?
        let boxstream = _shs.boxstream()?
        conn.expect(boxstream.header_size())?
        let conn_tag = recover tag conn end
        conn.set_notify(recover
          _BoxStreamNotify(
            conn_tag,
            remote_pk,
            consume boxstream
          )
        end)
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

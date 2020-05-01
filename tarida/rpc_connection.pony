use "net"
use "debug"
use "collections"

use "rpc"
use "sodium"
use "handlers"
use "package:ssbjson"

// SHS/RPC Ideas:
// On starting, our TCP server uses a Handshake notify, that performs the SHS mechanism.
// When/if the handshake succeeds, it changes the notify: the new one is a nested notify.
// The outter layer performs the box stream framing and enc/decryption.
// The next layer is the RPC mechanism, which also handles framing.
// The RPC layer can either be the final layer, or delegate RPC header parsing to another notifier.

class val RPCConnection
  let self_pk: Ed25519Public
  let remote_pk: Ed25519Public
  let _proxy: RPCConnectionServer

  new val create(proxy: RPCConnectionServer, self_pk': Ed25519Public, remote_pk': Ed25519Public) =>
    _proxy = proxy
    self_pk = self_pk'
    remote_pk = remote_pk'

  fun write(msg: RPCMsg iso): None =>
    _proxy._write(consume msg)

actor RPCConnectionServer
  let _socket: TCPConnection
  // A mapping of sequence number to handler on that stream
  embed _active_handlers: Map[U32, Handler]
  embed _buffer: RPCDecoder
  embed _conn: RPCConnection
  let _self_pk: Ed25519Public

  new create(raw_socket: TCPConnection, self_pk: Ed25519Public, self_sk: Ed25519Secret, other_pk: Ed25519Public) =>
    _socket = raw_socket
    _active_handlers = Map[U32, Handler]
    _buffer = RPCDecoder
    _conn = RPCConnection(this, self_pk, other_pk)
    _self_pk = self_pk

  be _write(msg: RPCMsg iso) =>
    let msg' = consume msg
    let repr = msg'.string()
    let bytes = RPCEncoder(consume msg')
    // If the message fits in a single chunk, send it directly
    // Otherwise, we split it into chunks, and deliver them using writev
    if bytes.size() <= 4096 then
      _socket.write(consume bytes)
    else
      Debug.out("RPCConnectionServer: scatter " + repr)
      _scatter_byte_chunks(consume bytes)
    end

  fun _scatter_byte_chunks(bytes': Array[U8] iso) =>
    var bytes = consume bytes'
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

  be _chunk(data: (String iso | Array[U8] iso)) =>
    _buffer.append(consume data)
    _try_process_chunks()

  fun ref _try_process_chunks() =>
    while true do
      try
        match _buffer.decode_msg()?
        | None => break
        | Goodbye =>
          Debug.out("RPCConnectionServer: goodbye")
          // The client is going away, clean up all resources
          _cleanup_handlers()
          _socket.dispose()
          break
        | let msg: RPCMsg iso => _process_msg(consume msg)
        end
      else
        Debug.err("RPCConnectionServer: _decode_packet bad packet")
        break
      end
    end

  fun ref _cleanup_handlers() =>
    for h in _active_handlers.values() do
      h.handle_disconnect(_conn)
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
        handler_for_msg.handle_call(_conn, consume msg)
      end

      return
    end

    // From now on, we know there's no handler for this message _yet_

    // If the original seq was a reply, and we don't have a handler,
    // simply drop the message on the floor
    if seq < 0 then
      Debug.err(
        "RPCConnectionServer: got reply to nonexistant handler at seq "
        + h_key.string()
        + ". Msg:"
        + msg.string()
      )

      return
    end

    // To be able to handle a message, we have to know how. Right now, the
    // only way to do that is to inspect the namespace of a json method.
    // So, the message _must_ be json. If it isn't, drop it on the floor.
    if msg.header().type_info isnt JSONMessage then
      Debug.err("RPCConnectionServer: can't handle msg " + msg.string())
      return
    end

    // The message also has to be a valid method. Again, drop it on the floor
    // if it isn't (it's not a method if it doesn't have a namespace)
    // TODO(borja): Look if there's a case where we get a legitimate non-json
    // message without an already active handler.
    let namespace = msg.namespace()
    if namespace is None then
      Debug.err("RPCConnectionServer: bad json method " + msg.string())
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
           "RPCConnectionServer: don't know how to handle "
           + namespace_str
           + " messages. Got msg: "
           + msg.string()
          )

      | let h: Handler =>
            h.handle_call(_conn, consume msg)
            _active_handlers(h_key) = h
      end
    end

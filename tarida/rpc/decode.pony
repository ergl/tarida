primitive _BinaryMessage
primitive _StringMessage
primitive _JSONMessage
primitive Goodbye

class RPCDecoder
  let _type_mask: U8 = 0x3
  let _end_mask: U8 = 0x4
  let _stream_mask: U8 = 0x5

  var _buffer: Array[U8] iso

  new create(size': USize = 0) =>
    """
    Create a new buffered decoder of the given initial capacity.
    """
    _buffer = recover Array[U8].create(size') end

  fun ref append(bytes: ByteSeq) =>
    """
    Append a number of bytes at the end of the decoder
    """
    _buffer.append(consume bytes)

  fun ref decode_msg(): (RPCMessage | Goodbye | None)? =>
    """
    Try to decode a message. If there's not enough data to get a complete message,
    `decode_msg` will return None, and the underlying buffer will be left intact.

    If the decoder finds bad data, it will error out, and the underlying buffer will
    be left intact.
    """
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

    let flags = (_buffer(0)? and 0xF)
    let req_number = _buffer_read_u32_be(5)?.i32()
    // Header was 9 bytes of 0, return zero
    if (flags == 0) and (req_number == 0) and (body_size == 0) then
      return Goodbye
    end

    let is_stream = (flags and _stream_mask) == _stream_mask
    let is_error = (flags and _end_mask) == _end_mask
    let kind = match (flags and _type_mask)
    | 0x0 => _BinaryMessage
    | 0x1 => _StringMessage
    | 0x2 => _JSONMessage
    else error end

    _buffer.trim_in_place(header_size)
    (let message_body, _buffer) = (consume _buffer).chop(body_size)

    recover
      match kind
      | _BinaryMessage =>
          RPCBinaryMessage(consume message_body, is_stream, is_error, req_number)
      | _StringMessage =>
          RPCStringMessage(String.from_iso_array(consume message_body), is_stream, is_error, req_number)
      | _JSONMessage =>
          RPCJsonMessage(String.from_iso_array(consume message_body), is_stream, is_error, req_number)
      end
    end

  fun ref _buffer_read_u32_be(offset: USize): U32? =>
    ifdef bigendian then
      _buffer.read_u32(offset)?
    else
      _buffer.read_u32(offset)?.bswap()
    end

  fun ref size(): USize =>
    """
    Return the size of the underlying buffer.
    """
    _buffer.size()

  fun ref clear() =>
    """
    Remove all elements from the decoder
    """
    _buffer.clear()

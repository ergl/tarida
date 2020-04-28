use "package:../ssbjson"
use "itertools"

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

  fun ref decode_msg(): (RPCMsg iso^ | Goodbye | None)? =>
    """
    Try to decode a message. If there's not enough data to get a complete message,
    `decode_msg` will return None, and the underlying buffer will be left intact.

    If the message is of type json, the decoder will try to decode it along the
    specifications on https://ssbc.github.io/scuttlebutt-protocol-guide/, that is,
    a request has a procedure name, a procedure type, and the procedure args. Some
    messages may have incomplete keys.

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
    | 0x0 => BinaryMessage
    | 0x1 => StringMessage
    | 0x2 => JSONMessage
    else error end

    _buffer.trim_in_place(header_size)

    let message_header = RPCMsgHeader(req_number, is_stream, is_error, kind)
    (let message_body, _buffer) = (consume _buffer).chop(body_size)

    recover
      match kind
      | BinaryMessage =>
          RPCMsg(message_header, consume message_body)
      | StringMessage =>
          RPCMsg(message_header, String.from_iso_array(consume message_body))
      | JSONMessage =>
          let inner_contents = _parse_rpc_json(
            String.from_iso_array(consume message_body)
          )?

          RPCMsg(message_header, consume inner_contents)
      end
    end

  fun ref _buffer_read_u32_be(offset: USize): U32? =>
    ifdef bigendian then
      _buffer.read_u32(offset)?
    else
      _buffer.read_u32(offset)?.bswap()
    end

  fun _parse_rpc_json(str: String iso)
    : (RPCjsonMethod iso^ | RPCrawJSON iso^)?
  =>
    let req_str = consume val str
    recover
      let msg = JsonDoc.>parse(req_str)?
      let msg_data = msg.get_data()
      match msg_data
      | let o: JsonObject =>
        let obj_data = o.get_data()
        if obj_data.contains("name") then
          let name_contents = obj_data("name")?
          match name_contents
          | let arr: JsonArray =>
            let name_arr = arr.get_data()
            // We're pretty sure this is a method
            _parse_rpc_method(name_arr, o)?
          else RPCrawJSON(msg_data) end
        else
          RPCrawJSON(msg_data)
        end
      else RPCrawJSON(msg_data) end
    end

  fun tag _parse_rpc_method(
    name_arr: Array[JsonType],
    rest: JsonObject)
    : RPCjsonMethod?
  =>
    let obj_data = rest.get_data()
    let method_namespace = name_arr(0)? as String
    let flat_name = Iter[JsonType](name_arr.values())
      .fold_partial[String]("", {(acc, elt): String? =>
        if acc == "" then
          acc + (elt as String)
        else
          acc + "." + (elt as String)
        end
      })?

    // FIXME(borja): Manyverse sends this message without `type` key
    // Ideally, we'd read ssb/manifest.json to see what the type is,
    // if the other side is not sending that key.
    let msg_type = match flat_name
    | "tunnel.isRoom" => "async"
    else obj_data("type")? as String end

    let args = obj_data("args")? as JsonArray
    RPCjsonMethod(method_namespace, flat_name, msg_type, args)

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

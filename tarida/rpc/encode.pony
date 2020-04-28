use "package:../ssbjson"
use "collections"

primitive RPCEncoder
  fun val apply(msg: RPCMsg iso): Array[U8] iso^ =>
    let packet_number = msg.header().packet_number
    let rpc_stream: U8 = if msg.header().is_stream then 0x1 else 0x0 end
    let rpc_end_error: U8 = if msg.header().is_end_error then 0x1 else 0x0 end
    let rpc_kind: U8 = match msg.header().type_info
    | BinaryMessage => 0x0
    | StringMessage => 0x1
    | JSONMessage => 0x2
    end

    let rpc_body = _encode_body(recover (consume msg).data() end)
    let rpc_body_size = rpc_body.size()

    let buffer = recover
      Array[U8].create(9 + rpc_body_size)
    end

    let flags = (rpc_stream << 3) or
                (rpc_end_error << 2) or
                rpc_kind

    buffer.push_u8(flags)
    ifdef bigendian then
      buffer.push_u32(rpc_body_size.u32())
    else
      buffer.push_u32(rpc_body_size.u32().bswap())
    end

    ifdef bigendian then
      buffer.push_u32(packet_number.u32())
    else
      buffer.push_u32(packet_number.u32().bswap())
    end

    // Copy everything from body
    buffer.copy_from(where src = rpc_body,
                           src_idx = 0,
                           dst_idx = 9,
                           len = rpc_body_size)

    buffer

  fun _encode_body(data: RPCData iso): Array[U8] val =>
    recover
      match (consume data)
      | let arr: Array[U8] iso => consume arr
      | let s: String iso => (consume s).array()
      | let raw: RPCrawJSON iso => _encode_raw_json(consume raw)
      | let method: RPCjsonMethod iso => _encode_json_method(consume method)
      end
    end

  fun _encode_raw_json(raw: RPCrawJSON iso): Array[U8] val =>
    match (consume raw).get_data()
    | let f: F64 => f.string().array()
    | let i: I64 => i.string().array()
    | let b: Bool => b.string().array()
    | let s: String => s.array()
    | let arr: this->JsonArray => arr.string().array()
    | let obj: this->JsonObject => obj.string().array()
    else
      // Pony complains about returning None, but the match is exhaustive
      // The only missing type is None, which is encoded as "null"
      "null".array()
    end

  fun _encode_json_method(method': RPCjsonMethod iso): Array[U8] val =>
    let method = consume ref method'
    // FIXME(borja): Ugly hack because I can't turn an Array[String] into Array[JsonType]
    let name_arr = method.name.split(".")
    let j_array = Array[JsonType].create(name_arr.size())
    for v in (consume name_arr).values() do
      j_array.push(v)
    end

    let contents = Map[String, JsonType].create(3)
    contents("name") = JsonArray.from_array(j_array)
    contents("args") = method.args
    contents("type") = method.msg_type
    JsonObject.from_map(contents).string().array()

use "package:../ssbjson"
use "itertools"
use "collections"

class RPCrawJSON
  let _data: JsonType
  new create(data: JsonType) => _data = data
  fun get_data(): this->JsonType! => _data
  fun string(): String =>
    match _data
    | let f: F64 => f.string()
    | let i: I64 => i.string()
    | let b: Bool => b.string()
    | None => "null"
    | let s: String => s
    | let arr: this->JsonArray => arr.string()
    | let obj: this->JsonObject => obj.string()
    end

type RPCData is ( Array[U8]
                | String ref
                | RPCjsonMethod
                | RPCrawJSON ref
                )

primitive BinaryMessage
primitive StringMessage
primitive JSONMessage
type RPCMsgTypeInfo is (BinaryMessage | StringMessage | JSONMessage)

// Header info for the RPC message
class val RPCMsgHeader
  let packet_number: I32
  let is_stream: Bool
  let is_end_error: Bool
  let type_info: RPCMsgTypeInfo

  new val create(
    packet_number': I32,
    is_stream': Bool,
    is_end_error': Bool,
    type_info': RPCMsgTypeInfo)
  =>
    packet_number = packet_number'
    is_stream = is_stream'
    is_end_error = is_end_error'
    type_info = type_info'

  fun string(): String =>
    let p_s = packet_number.string()
    let s_s = is_stream.string()
    let e_s = is_end_error.string()
    let t_s = match type_info
    | BinaryMessage => "binary"
    | StringMessage => "string"
    | JSONMessage => "json"
    end

    "RPCMsgHeader[req=" + (consume p_s) + ", stream=" + (consume s_s) + ", error/end=" + (consume e_s) + ", type=" + t_s + "]"

class RPCMsg
  let _data: RPCData
  let _header: RPCMsgHeader

  new create(header': RPCMsgHeader, data': RPCData iso) =>
    _header = header'
    _data = consume ref data'

  new error_close_from(from: RPCMsgHeader, payload: RPCData iso) =>
    _data = consume ref payload
    _header = RPCMsgHeader(where packet_number' = from.packet_number.neg(),
                                 is_stream' = from.is_stream,
                                 type_info' = from.type_info,
                                 is_end_error' = true)

  new json_error_from(from: RPCMsgHeader, error_msg: String) =>
    // TODO(borja): Are all errors like this?
    let error_payload = recover
      let contents = Map[String, JsonType].create(3)
      contents("name") = "Error"
      contents("message") = error_msg
      contents("stack") = "" // Can omit?
      RPCrawJSON(JsonObject.from_map(contents))
    end

    _data = consume ref error_payload
    _header = RPCMsgHeader(where packet_number' = from.packet_number.neg(),
                                 is_stream' = from.is_stream,
                                 type_info' = JSONMessage,
                                 is_end_error' = true)

  new reply_from(from: RPCMsgHeader, payload: RPCData iso) =>
    _data = consume ref payload
    _header = RPCMsgHeader(where packet_number' = from.packet_number.neg(),
                                 is_end_error' = from.is_end_error,
                                 is_stream' = from.is_stream,
                                 type_info' = from.type_info)

  fun header(): RPCMsgHeader => _header
  fun data(): this->RPCData^ => _data
  fun namespace(): (String | None) =>
    match _data
    | let req: this->RPCjsonMethod => req.namespace
    else None end

  fun string(): String =>
    let h_s = _header.string()
    let body_s = match _data
    | let s: this->String ref => s.clone()
    | let a: this->Array[U8] =>
        let c = recover Array[U8] end
        for v in a.values() do
          c.push(v)
        end
        String.from_array(consume c)
    | let resp: this->RPCrawJSON => "RawJSON[" + resp.string() + "]"
    | let req: this->RPCjsonMethod =>
        let ns = req.namespace
        let name = req.name
        let req_type = req.msg_type
        let args = req.args.string()
        "<namespace=" + ns + ", name=" + name + ", type=" + req_type + ", args=" + args + ">"
    end

    h_s + " " + body_s

class RPCjsonMethod
  var namespace: String
  var name: String
  var msg_type: String
  var args: JsonArray

  new create(
    namespace': String,
    name': String,
    msg_type': String,
    args': JsonArray)
  =>
    namespace = namespace'
    name = name'
    msg_type = msg_type'
    args = args'

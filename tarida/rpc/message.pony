use "package:../ssbjson"
use "itertools"

type RPCrawJson is JsonDoc
type RPCData is ( Array[U8]
                | String ref
                | RPCjsonMethod
                | RPCrawJson
                | JsonDoc
                )

// Header info for the RPC message
class val RPCMsgHeader
  let packet_number: I32
  let is_stream: Bool
  let is_end_error: Bool

  new val create(seq': I32, stream': Bool, end_error': Bool) =>
    packet_number = seq'
    is_stream = stream'
    is_end_error = end_error'

interface _RPCMessage
  fun header(): RPCMsgHeader
  fun string(): String
  fun data(): this->RPCData^

type RPCMessage is (RPCBinaryMessage | RPCStringMessage | RPCJsonMessage)

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

class RPCBinaryMessage is _RPCMessage
  let _header: RPCMsgHeader
  let _data: Array[U8] ref

  new create(
    data': Array[U8] iso,
    stream: Bool,
    error_end: Bool,
    n: I32)
  =>
    _header = RPCMsgHeader(n, stream, error_end)
    _data = consume ref data'

  fun header(): RPCMsgHeader => _header
  fun string(): String =>
    let a = recover Array[U8] end
    for v in _data.values() do
      a.push(v)
    end
    String.from_array(consume a)

  fun data(): this->Array[U8] => _data

class RPCStringMessage is _RPCMessage
  let _header: RPCMsgHeader
  let _data: String ref

  new create(
    data': String iso,
    stream: Bool,
    error_end: Bool,
    n: I32
  ) =>
    _header = RPCMsgHeader(n, stream, error_end)
    _data = consume ref data'

  fun header(): RPCMsgHeader => _header
  fun string(): String => _data.clone()
  fun data(): this->String ref => _data

class RPCJsonMessage is _RPCMessage
  let _header: RPCMsgHeader
  let _inner_namespace: (String | None)
  let _data: (RPCjsonMethod | RPCrawJson)

  new create(
    data': (RPCjsonMethod iso | RPCrawJson iso),
    stream: Bool,
    error_end: Bool,
    n: I32
  ) =>
    _header = RPCMsgHeader(n, stream, error_end)
    _data = consume ref data'
    _inner_namespace = match _data
    | let req: this->RPCjsonMethod => req.namespace
    else None end

  fun header(): RPCMsgHeader => _header
  fun string(): String =>
    match _data
    | let resp: this->RPCrawJson =>
      "RawJSON[" + resp.string() + "]"
    | let req: this->RPCjsonMethod =>
      "<namespace=" + req.namespace + ", name=" + req.name + ", type=" + req.msg_type + ", args=" + req.args.string() + ">"
    end

  fun data(): (this->RPCrawJson | this->RPCjsonMethod) =>
    _data

  fun namespace(): (String | None) =>
    _inner_namespace

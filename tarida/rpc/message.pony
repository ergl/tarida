use "package:../ssbjson"
use "itertools"

type RPCrawJson is JsonDoc
type RPCData is ( Array[U8]
                | String ref
                | RPCjsonMethod
                | RPCrawJson
                | JsonDoc
                )

interface _RPCMessage
  fun is_stream(): Bool
  fun is_end_error(): Bool
  fun packet_number(): I32
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
  let _seq: I32
  let _stream: Bool
  let _error: Bool
  let _data: Array[U8] ref

  new create(
    data': Array[U8] iso,
    stream: Bool,
    error_end: Bool,
    n: I32)
  =>
    _seq = n
    _stream = stream
    _error = error_end
    _data = consume ref data'

  fun is_stream(): Bool => _stream
  fun is_end_error(): Bool => _error
  fun packet_number(): I32 => _seq
  fun string(): String =>
    let a = recover Array[U8] end
    for v in _data.values() do
      a.push(v)
    end
    String.from_array(consume a)

  fun data(): this->Array[U8] => _data

class RPCStringMessage is _RPCMessage
  let _seq: I32
  let _stream: Bool
  let _error: Bool
  let _data: String ref

  new create(
    data': String iso,
    stream: Bool,
    error_end: Bool,
    n: I32
  ) =>
    _seq = n
    _stream = stream
    _error = error_end
    _data = consume ref data'

  fun is_stream(): Bool => _stream
  fun is_end_error(): Bool => _error
  fun packet_number(): I32 => _seq
  fun string(): String => _data.clone()
  fun data(): this->String ref => _data

class RPCJsonMessage is _RPCMessage
  let _seq: I32
  let _stream: Bool
  let _error: Bool
  let _inner_namespace: (String | None)
  let _data: (RPCjsonMethod | RPCrawJson)

  new create(
    data': (RPCjsonMethod iso | RPCrawJson iso),
    stream: Bool,
    error_end: Bool,
    n: I32
  ) =>
    _seq = n
    _stream = stream
    _error = error_end
    _data = consume ref data'
    _inner_namespace = match _data
    | let req: this->RPCjsonMethod => req.namespace
    else None end

  fun is_stream(): Bool => _stream
  fun is_end_error(): Bool => _error
  fun packet_number(): I32 => _seq
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

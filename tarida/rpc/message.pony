type RPCMessage is (RPCBinaryMessage val | RPCStringMessage val | RPCJsonMessage val)

class val RPCBinaryMessage
  let _seq: I32
  let _stream: Bool
  let _error: Bool
  let data: Array[U8] val

  new val create(data': Array[U8] iso, stream: Bool, error_end: Bool, n: I32) =>
    _seq = n
    _stream = stream
    _error = error_end
    data = consume data'

  fun is_stream(): Bool => _stream
  fun is_end_error(): Bool => _error
  fun packet_number(): I32 => _seq
  fun string(): String => String.from_array(data)

class val RPCStringMessage
  let _seq: I32
  let _stream: Bool
  let _error: Bool
  let data: String

  new val create(data': String iso, stream: Bool, error_end: Bool, n: I32) =>
    _seq = n
    _stream = stream
    _error = error_end
    data = consume data'

  fun is_stream(): Bool => _stream
  fun is_end_error(): Bool => _error
  fun packet_number(): I32 => _seq
  fun string(): String => data

class val RPCJsonMessage
  let _seq: I32
  let _stream: Bool
  let _error: Bool
  let data: String

  new val create(data': String iso, stream: Bool, error_end: Bool, n: I32) =>
    _seq = n
    _stream = stream
    _error = error_end
    data = consume data'

  fun is_stream(): Bool => _stream
  fun is_end_error(): Bool => _error
  fun packet_number(): I32 => _seq
  fun string(): String => data

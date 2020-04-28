use "debug"
use t = "time"

use "package:.."
use "package:../.."
use "package:../../rpc"
use "package:../../ssbjson"

class iso _PingTimer is t.TimerNotify
  let _conn: RPCConnection
  let _header: RPCMsgHeader

  fun ref cancel(timer: t.Timer) => None

  new iso create(conn: RPCConnection, header: RPCMsgHeader) =>
    _conn = conn
    _header = header

  fun ref apply(timer: t.Timer, count: U64): Bool =>
    let payload = recover RPCrawJSON(I64.from[U64](t.Time.millis())) end
    _conn.write(recover RPCMsg.reply_from(_header, consume payload) end)
    true

actor GossipHandler is Handler
  var _ping_timeout: I64 = 0
  let _timer_wheel: t.Timers = t.Timers
  var _active_timer: (t.Timer tag | None) = None

  be handle_init(conn: RPCConnection) => None // TODO
  be handle_disconnect(conn: RPCConnection) =>
    match _active_timer
    | let handle: t.Timer tag =>
        _timer_wheel.cancel(handle)
        _active_timer = None
    else None end

  be handle_call(conn: RPCConnection, msg: RPCMsg iso) =>
    let msg' = consume ref msg
    match msg'.data()
    | let method: RPCjsonMethod => _dispatch_method(conn, msg'.header(), method)
    else Debug.out("gossip: don't know how to handle " + msg'.string()) end // TODO

  fun ref _dispatch_method(conn: RPCConnection, header: RPCMsgHeader, method: RPCjsonMethod) =>
    match method.name
    | "gossip.ping" => _handle_ping(conn, header, method.args)
    else Debug.err("gossip: don't know how to handle" + method.name) end

  fun ref _handle_ping(conn: RPCConnection, header: RPCMsgHeader, args: JsonArray) =>
    """
    The args for timeout should be [{"timeout":300000}]
    """
    let json_array = args.data
    try
      let arg_obj = json_array(0)? as JsonObject
      let timeout = arg_obj.data("timeout")? as I64

      // If there's an active timer, reset it
      match _active_timer
      | let handle: t.Timer tag => _timer_wheel.cancel(handle)
      else None end

      let ping_timer = _PingTimer(conn, header)
      let handle = t.Timer(where notify = consume ping_timer,
                                 expiration = 0, // Fire immediately
                                 interval = t.Nanos.from_millis(timeout.u64()))

      _active_timer = recover tag handle end
      _timer_wheel(consume handle)
    else
      Debug.err("gossip.ping bad args")
    end

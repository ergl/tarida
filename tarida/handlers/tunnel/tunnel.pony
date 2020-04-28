use "debug"
use "package:.."
use "package:../.."
use "package:../../rpc"
use "package:../../ssbjson"

// Docs: look at https://github.com/staltz/ssb-room/blob/master/tunnel/server.js
// and https://github.com/ssbc/ssb-tunnel

actor TunnelHandler is Handler
  be handle_init(conn: RPCConnection) => None // TODO
  be handle_disconnect(conn: RPCConnection) => None // TODO
  be handle_call(conn: RPCConnection, msg: RPCMsg iso) =>
    Debug.out("TunnelHandler: received " + msg.string())
    let msg' = consume ref msg
    match msg'.data()
    | let method: RPCjsonMethod => _dispatch_method(conn, msg'.header(), method)
    else Debug.out("TunnelHandler: don't know how to handle " + msg'.string()) end // TODO

  fun ref _dispatch_method(
    conn: RPCConnection,
    header: RPCMsgHeader,
    method: RPCjsonMethod)
  =>

    match method.name
    | "tunnel.isRoom" => conn.write(recover RPCMsg.reply_from(header, recover RPCrawJSON(true) end) end)
    | "tunnel.endpoints" => None // Subscriptions, send
    else
      Debug.err("TunnelHandler: don't know how to handle " + method.name)
    end

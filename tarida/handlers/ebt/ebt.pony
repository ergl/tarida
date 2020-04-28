use "debug"
use "package:.."
use "package:../.."
use "package:../../rpc"
use "package:../../ssbjson"

actor EBTHandler is Handler
  be handle_init(conn: RPCConnection) => None // TODO
  be handle_disconnect(conn: RPCConnection) => None // TODO

  be handle_call(conn: RPCConnection, msg: RPCMsg iso) =>
    let msg' = consume ref msg
    match msg'.data()
    | let raw: RPCrawJSON => Debug.out("ebt: got raw msg " + raw.string())
    | let method: RPCjsonMethod => _dispatch_method(conn, msg'.header(), method)
    else None end // TODO(borja): See if ebt ever sends binary/string msgs

  fun ref _dispatch_method(conn: RPCConnection, header: RPCMsgHeader, method: RPCjsonMethod) =>
    match method.name
    | "ebt.replicate" => _handle_replicate(conn, header, method.args)
    else Debug.err("ebt: don't know how to handle " + method.name) end

  fun ref _handle_replicate(conn: RPCConnection, header: RPCMsgHeader, args: JsonArray) =>
    conn.write(recover
      RPCMsg.json_error_from(header, "tarida doesn't support ebt replication yet")
    end)

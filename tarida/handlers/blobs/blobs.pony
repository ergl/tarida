use "debug"
use "package:.."
use "package:../.."
use "package:../../rpc"
use "package:../../ssbjson"

actor BlobsHandler is Handler
  be handle_init(conn: RPCConnection) => None // TODO
  be handle_disconnect(conn: RPCConnection) => None // TODO
  be handle_call(conn: RPCConnection, msg: RPCMsg iso) =>
    let msg' = consume ref msg
    match msg'.data()
    | let method: RPCjsonMethod => _dispatch_method(conn, msg'.header(), method)
    else Debug.out("blobs: don't know how to handle " + msg'.string()) end // TODO

  fun ref _dispatch_method(conn: RPCConnection, header: RPCMsgHeader, method: RPCjsonMethod) =>
    match method.name
    | "blobs.createWants" => _handle_wants(conn, header)
    else Debug.out("blobs: don't know how to handle " + method.name) end

  fun ref _handle_wants(conn: RPCConnection, header: RPCMsgHeader) =>
    // Send an empty `wants`
    conn.write(recover
      RPCMsg.reply_from(header, recover RPCrawJSON(JsonObject) end)
    end)

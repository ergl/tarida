use "debug"
use "package:.."
use "package:../.."
use "package:../../rpc"

actor BlobsHandler is Handler
  be handle_init(conn: RPCConnection) =>
    // TODO
    Debug.out("blobs: init!")

  be handle_disconnect(conn: RPCConnection) =>
    // TODO
    Debug.out("blobs: handle_disconnect!")

  be handle_call(conn: RPCConnection, msg: RPCMsg iso) =>
    // TODO
    Debug.out("blobs: handle_call of " + msg.string())

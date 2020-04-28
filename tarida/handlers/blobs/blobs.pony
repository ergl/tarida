use "debug"
use "package:.." // For `Handler`
use "package:../.." // For `RPCConnection`
use "package:../../rpc" // For `RPCMessage`

actor BlobsHandler is Handler
  be handle_init(conn: RPCConnection) =>
    // TODO
    Debug.out("blobs: init!")

  be handle_disconnect(conn: RPCConnection) =>
    // TODO
    Debug.out("blobs: handle_disconnect!")

  be handle_call(conn: RPCConnection, msg: RPCMsg iso) =>
    // TODO
    Debug.out("blobs: handle_call of " + (consume msg).string())

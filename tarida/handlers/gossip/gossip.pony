use "debug"
use "package:.." // For `Handler`
use "package:../.." // For `RPCConnection`
use "package:../../rpc" // For `RPCMessage`

actor GossipHandler is Handler
  be handle_init(conn: RPCConnection) =>
    // TODO
    Debug.out("gossip: init!")

  be handle_disconnect(conn: RPCConnection) =>
    // TODO
    Debug.out("gossip: handle_disconnect!")

  be handle_call(conn: RPCConnection, msg: RPCMessage iso) =>
    // TODO
    Debug.out("gossip: handle_call of " + (consume msg).string())

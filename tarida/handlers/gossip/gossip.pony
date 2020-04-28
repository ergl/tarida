use "debug"
use "package:.."
use "package:../.."
use "package:../../rpc"

actor GossipHandler is Handler
  be handle_init(conn: RPCConnection) =>
    // TODO
    Debug.out("gossip: init!")

  be handle_disconnect(conn: RPCConnection) =>
    // TODO
    Debug.out("gossip: handle_disconnect!")

  be handle_call(conn: RPCConnection, msg: RPCMsg iso) =>
    // TODO
    Debug.out("gossip: handle_call of " + msg.string())

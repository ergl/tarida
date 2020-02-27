use "package:.."
use "package:../rpc"

interface tag Handler
  be handle_init(conn: RPCConnection)
  be handle_disconnect(conn: RPCConnection)
  be handle_call(conn: RPCConnection, msg: RPCMessage iso)

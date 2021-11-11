use "../sodium"

use "net"

interface iso BoxStreamNotify is TCPConnectionNotify
  fun ref connected_to(conn: TCPConnection, peer_pk: Ed25519Public): None =>
    None

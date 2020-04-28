use "package:./gossip"
use "package:./blobs"
use "package:./ebt"
use "package:./tunnel"

primitive HandlerRegistrar
  fun apply(namespace: String): (Handler | None) =>
    match namespace
    | "gossip" => GossipHandler
    | "blobs" => BlobsHandler
    | "ebt" => EBTHandler
    | "tunnel" => TunnelHandler
    else None
    end

use "package:./gossip"
use "package:./blobs"
use "package:./ebt"

primitive HandlerRegistrar
  fun apply(namespace: String): (Handler | None) =>
    match namespace
    | "gossip" => GossipHandler
    | "blobs" => BlobsHandler
    | "ebt" => EBTHandler
    else None
    end

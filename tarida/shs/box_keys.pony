// TODO(borja): BoxKeys.apply() returns a BoxStream
// BoxStream will encrypt and decrypt messages you give it, and automatically
// increment or update the nonces as it goes.
// This way it can be used from a TCPConnectionNotify to transparently
// encrypt/decrypt messages in both ways
//
// By having a private type as its only argument, we can make sure that only
// this package can craft a correct BoxStream object
// Another option would be to use capabilites a la AmbientAuth, etc

class iso BoxStream
  new iso create(keys: _BoxKeys) =>
    None // TODO


primitive BoxKeys
  fun apply(shs: (HandshakeServer | HandshakeClient)): BoxStream iso^? =>
    BoxStream(shs._full_secret()?)
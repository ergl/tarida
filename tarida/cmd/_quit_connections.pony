use "bureaucracy"
use "signals"

class _QuitConnections is SignalNotify
  let _c: Custodian

  new iso create(c: Custodian) => _c = c

  fun ref apply(count: U32): Bool =>
    _c.dispose()
    true

primitive _RegisterHandler
  fun apply(custodian: Custodian) =>
    """
    Quit all connections when the user quits
    """
    SignalHandler(_QuitConnections(custodian), Sig.term())

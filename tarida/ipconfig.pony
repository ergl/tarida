use "files"
use "process"

primitive IPConfig
  fun apply(auth: AmbientAuth, iface: String val, cb: {(String)} val, cb_err: {()} val) =>
    ifdef osx then // Not sure on other platforms, might as well error
      try
        let path = FilePath(auth, "/usr/sbin/ipconfig")?
        let args = recover val [as String: "ipconfig"; "getifaddr"; iface] end
        let pm = ProcessMonitor(auth, auth, _Client(cb, cb_err), path, args, [])
        pm.done_writing()
      else
        cb_err.apply()
      end
    else
      cb_err.apply()
    end

class iso _Client is ProcessNotify
    let _cb: {(String)} val
    let _err: {()} val

  new iso create(cb: {(String)} val, cb_err: {()} val) =>
    _cb = cb
    _err = cb_err

  fun ref stdout(proc: ProcessMonitor ref, data: Array[U8] iso) =>
    let s = String.from_iso_array(consume data)
    s.strip()
    _cb.apply(consume s)

  fun ref created(proc: ProcessMonitor ref) => None
  fun ref stderr(proc: ProcessMonitor ref, data: Array[U8] iso) => None
  fun ref failed(proc: ProcessMonitor ref, err: ProcessError) => _err.apply()
  fun ref dispose(proc: ProcessMonitor ref, child_exit_code: I32) => None

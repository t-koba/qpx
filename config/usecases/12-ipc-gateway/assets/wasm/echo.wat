(module
  (type $fd_write_t (func (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (type $fd_write_t)))
  (memory (export "memory") 1)
  (data (i32.const 8) "Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nok from qpxf wasm\n")
  (func (export "_start")
    i32.const 0
    i32.const 8
    i32.store
    i32.const 4
    i32.const 62
    i32.store
    i32.const 1
    i32.const 0
    i32.const 1
    i32.const 20
    call $fd_write
    drop))

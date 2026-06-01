## badgate

This is a simple gateway service which allows you to process incoming TCP connections with Lua scripts.

### API reference

There is a example program in `http.example.lua` 

- `gateway.run(handler_fn(conn, pkt))`
- `conn:send(data) -> bytes_sent`
- `conn:close()`
- `conn:peer() -> ip, port`
- `conn:sockname() -> ip, port`
- `pkt:len() -> integer`
- `pkt:tostring() -> string`
- `pkt:write(off, data)`
- `pkt:view(off, len) -> pkt`

*GLHF!*
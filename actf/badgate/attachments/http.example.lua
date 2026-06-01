local function trim_line_end(s)
    return (s:gsub("\r$", ""))
end

local function parse_request(req)
    local head = req:match("^(.-)\r?\n\r?\n") or req
    local first = head:match("([^\r\n]+)") or ""
    local method, path, version = first:match("^(%S+)%s+(%S+)%s+(%S+)$")
    local headers = {}

    for raw_line in head:gmatch("[^\n]+") do
        local line = trim_line_end(raw_line)
        if line ~= first then
            local k, v = line:match("^([^:]+):%s*(.*)$")
            if k then
                headers[k:lower()] = v
            end
        end
    end

    return {
        method = method,
        path = path,
        version = version,
        headers = headers,
    }
end

local function make_body(conn, req, raw)
    local peer_ip, peer_port = conn:peer()
    local listen_ip, listen_port = conn:sockname()
    local host = req.headers.host or "-"

    return table.concat({
        "lua gateway http demo",
        "method: " .. (req.method or "-"),
        "path: " .. (req.path or "-"),
        "version: " .. (req.version or "-"),
        "host: " .. host,
        string.format("peer: %s:%s", peer_ip or "-", peer_port or "-"),
        string.format("local: %s:%s", listen_ip or "-", listen_port or "-"),
        "request-bytes: " .. #raw,
        "",
    }, "\n")
end

local function send_response(conn, status, body, extra_headers)
    extra_headers = extra_headers or {}
    extra_headers[#extra_headers + 1] = "Content-Type: text/plain; charset=utf-8"
    extra_headers[#extra_headers + 1] = "Content-Length: " .. #body
    extra_headers[#extra_headers + 1] = "Connection: close"

    local resp = table.concat({
        "HTTP/1.1 " .. status,
        table.concat(extra_headers, "\r\n"),
        "",
        body,
    }, "\r\n")

    conn:send(resp)
    conn:close()
end

local function on_request(conn, pkt)
    local raw = pkt:tostring()
    local req = parse_request(raw)

    if not req.method then
        send_response(conn, "400 Bad Request", "bad request\n")
        return
    end

    if req.path == "/" then
        send_response(conn, "200 OK", make_body(conn, req, raw))
        return
    end

    if req.path == "/AAA" then
        send_response(conn, "200 OK", "@Eclipsky:WuYan is a big turtle\n")
        return
    end

    send_response(conn, "404 Not Found", "not found\n")
end

gateway.run(on_request)
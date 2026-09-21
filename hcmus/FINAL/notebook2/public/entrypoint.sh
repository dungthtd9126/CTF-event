#!/bin/bash
./prob 5000 &
prob_pid=$!

# wait for the service to come up
until (exec 3<>/dev/tcp/127.0.0.1/5000) 2>/dev/null; do sleep 0.1; done

# i want to wrote a goodluck note :D
(
    exec 3<>/dev/tcp/127.0.0.1/5000
    cat /home/pwn/goodluck.bin >&3
    cat <&3 >/dev/null
) &

sleep 0.3
wait "$prob_pid"

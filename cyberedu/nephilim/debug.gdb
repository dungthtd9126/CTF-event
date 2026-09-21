set pagination off
target remote 127.0.0.1:3636

break *0xffffffff81090980
commands
  silent
  printf "CALL_USERMODEHELPER\n"
  info registers rdi rsi rdx rcx rip rsp
  x/16gx $rdi
  x/8gx $rsi
  x/8gx $rdx
  continue
end

break *0xffffffff81236ed0
condition 2 ($rdi >= 0xffff888000000000 && $rdi < 0xffffc88000000000)
commands
  silent
  printf "KERNEL_EXECVE\n"
  info registers rdi rsi rdx rcx rip rsp
  x/8gx $rdi
  x/8gx $rsi
  x/8gx $rdx
  detach
  quit
end

continue

set pagination off
set confirm off
set debuginfod enabled off
target remote 127.0.0.1:3641

break *0xffffffff81090980
commands
  silent
  printf "UMH entry\n"
  info registers rdi rsi rdx rcx rsp
  continue
end

break *0xffffffff81090b98
commands
  silent
  printf "kernel_execve returned\n"
  info registers rax rbx rsp
  continue
end

break *0xffffffff81236ed0
commands
  silent
  printf "kernel_execve entry\n"
  info registers rdi rsi rdx rcx rsp
  x/8gx $rdi
  x/8gx $rsi
  x/8gx $rdx
  continue
end

continue

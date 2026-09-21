set pagination off
set confirm off
set debuginfod enabled off
target remote 127.0.0.1:3640

break *0xffffffff81090980
commands
  silent
  printf "UMH entry\n"
  info registers rdi rsi rdx rcx rsp
  x/16gx $rdi
  x/8gx $rsi
  x/8gx $rdx
  continue
end

break *0xffffffff810909b4
commands
  silent
  printf "UMH allocation returned\n"
  info registers rax r12 rbp rbx rsp
  x/12gx $rax
  continue
end

break *0xffffffff81090b87
commands
  silent
  printf "UMH async before exec\n"
  info registers rbx rsp
  x/12gx $rbx
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

<img width="666" height="237" alt="image" src="https://github.com/user-attachments/assets/349ee224-8983-4a0a-a7df-ad191eb6b108" /># pragyan
## Dirty
- This is a easy bof challenge

<img width="704" height="270" alt="image" src="https://github.com/user-attachments/assets/082fdfbf-dba1-4035-a9cd-67b7fdf4d4c8" />

- It also has PIE OFF

<img width="666" height="237" alt="image" src="https://github.com/user-attachments/assets/c575046d-a374-417b-86be-26f839798ae7" />

- So i will use simple method, overwrite saved rip to puts plt to leak libc because rdi is storing a ptr to a libc address

  <img width="1253" height="745" alt="image" src="https://github.com/user-attachments/assets/0ab95963-9083-43ba-b527-4506cdbbd50e" />

- After got libc, i can then rop chain it to shell by pop rdi, system


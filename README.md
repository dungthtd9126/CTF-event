# pascal
## note-taker
- This is a basic fmt string challenge

<img width="603" height="672" alt="image" src="https://github.com/user-attachments/assets/a6343944-35a2-44a0-be40-07fb1f13c7a0" />

- It has a while do loop, enabling me to leave or stay in the loop by choice

- So i just need to leak libc, stack then fmt str overwrite saved rip of main with one gadget and leave the loop --> done
## malta
- This challenge is pretty easy, it has logic bug

- The bug is in the line 108, the program check balance >= price[idx]*num, if true then it will print product name and it's recipe

<img width="1243" height="682" alt="image" src="https://github.com/user-attachments/assets/4db654db-79e4-4044-bea8-dc4af719ee57" />

- I can choose what ever num i want. So i just input num = 0 then it will auto true and print the flag in option 10

## Heap
- The challenge's heap layout is different from the past and i can't run patched challenge so may be i can't solve it now

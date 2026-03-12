# Apoorv-CTF
## havok
- This challenge has 2 main bugs: bof and integer bug

- We can see integer bug in calibrate_rings function if look carefully

<img width="1529" height="859" alt="image" src="https://github.com/user-attachments/assets/48d9a596-62c2-4149-9bfc-dd723429bd81" />

- It is pretty hard to see that bug in this challenge

- The bug is in this line: <b> if ( (__int16)raw > 3 ) </b>

- 

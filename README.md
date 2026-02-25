# eschaton
## legacy
- This is a format str challenge

- The bug is inside the maint function

<img width="736" height="595" alt="image" src="https://github.com/user-attachments/assets/13388115-530d-43ae-a064-40b3e99e4f97" />

<img width="1273" height="690" alt="image" src="https://github.com/user-attachments/assets/60fa6f44-a123-40d8-953f-d8c8fee367bb" />

- The bug stay in snprintf at line 18

- It copies pw variable, which is controlled by my input, to s[idx]

- As you can see in line 17, the correct way to use snprintf is to use a string combine with fmt str, then the next argument will be variable we want to show

- But line 18 copy full value of pw to s[idx] without any check

- That means i have full control of pw, leading to fmt str bug

- So i just need to fmt str to leak stack, binary

<img width="1816" height="279" alt="image" src="https://github.com/user-attachments/assets/eb06b5f4-b147-494c-a9cf-4557e2803d58" />

- Then overwrite saved rip of maint to line 25 of FLAG function to print out flag

<img width="1078" height="517" alt="image" src="https://github.com/user-attachments/assets/513c7520-4e9b-48ad-bff3-afa7c61eec02" />

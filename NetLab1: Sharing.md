***NetLab1: Sharing***

![image](https://github.com/user-attachments/assets/560e74d8-b473-4d88-bf30-bfb64b05aac9)

Khi tải về chúng ta được 1 file nén mà khi giải nén ra chúng ta dược 1 file pcap mở ra bằng wireshanks tui ```object list``` > ```SMB```` được 2 file ```netlab1.7z``` và ```password.txt```

![image](https://github.com/user-attachments/assets/0df3a664-e51c-4c33-8b01-6fafb3aa339f)

mở file ```netlab1.7z``` cần pass và pass lấy từ file ```password.txt``` : ```SMBprotocol```

```linux
╭─   nart   ~                                                                                ✔  05:22:34 PM  ─╮
╰─❯ strings %5cpassword.txt                                                                                          ─╯
SMBprotocol
```
giải nén chúng ta được 1 file ```netlab1.db``` và nó chạy bằng SQlite nên chúng ta sẽ mở nó bằng wed [này](https://inloop.github.io/sqlite-viewer/). Chúng ta được flag

![image](https://github.com/user-attachments/assets/53223df7-fcc1-447e-a641-b85da16c20a8)
![image](https://github.com/user-attachments/assets/5e12ee4c-0fd3-434a-912a-1702a0f65171)

flag : ```Flag{NetLab1_N0w_y0u_kn0w_SMB??}```

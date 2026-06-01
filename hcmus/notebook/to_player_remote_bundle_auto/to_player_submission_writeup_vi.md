
## Ý tưởng chính

Bug nằm trong custom allocator `Cage`. Khi một chunk được free và merge lùi với chunk free phía trước, metadata `priv_size` của chunk kế tiếp bị cập nhật sai. Kết quả là có thể tạo ra **hai free chunk chồng lấn nhau**, rồi dùng overlap đó để ghi đè metadata `Note` của một `Book` khác. Từ đây ta có primitive leak tùy ý bằng cách forge các cặp `(size, data)` của `Note`. 

## Tạo overlap

Script chia heap thành nhiều `group`. Với mỗi group, nó cấp phát 4 note theo layout:

- `A = 0x170`
- `B = 0x170`
- `C = 0x2f0`
- `D = 0xf0`

sau đó free theo thứ tự `B -> A -> C`. Sau bước này, script chuyển sang `book` khác rồi quay lại `book 0` để xin lại chunk chồng lấn và ghi payload vào vùng đó. Đây chính là phần `setup_group()` và `setup_scan_groups()` trong `solve.py`. 

## Arbitrary read

Mỗi `Note` có dạng:

```c
struct Note {
    uint64_t size;
    char *data;
};
```

Khi phần đầu mảng `Note` bị overlap, script forge các slot thành `(size, addr)`. Lúc gọi read note, chương trình sẽ `write(1, data, size)`, nên ta leak được dữ liệu ở địa chỉ tùy ý. Phần này được hiện thực bởi `writer_payload()`, `leak_specs()`, `leak()`, và `leak_qword()`. fileciteturn4file0

## Leak stack, PIE và libc

Script không dùng `/proc/self/maps`. Thay vào đó nó brute-force vùng stack user-space bằng `probe_readable()`, tìm một địa chỉ readable làm anchor, rồi refine lại thành cả stack mapping qua `find_stack_anchor()` và `refine_stack_mapping()`. Sau đó script dump stack, parse `auxv`, lấy `AT_PHDR` và suy ra PIE base trong `find_auxv_and_pie()`. fileciteturn4file0

Khi đã có PIE, script leak `write@GOT`, rồi đi lùi từng page để tìm ELF header `\x7fELF`, từ đó suy ra libc base bằng `find_elf_base()`. fileciteturn4file0

## Recover pointer_guard

glibc mã hóa function pointer trong `__exit_funcs` bằng pointer mangling. Script đọc `__exit_funcs`, tìm một entry destructor thuộc về binary, rồi khôi phục `pointer_guard` bằng công thức đảo `rol/ror`. Phần này nằm trong `recover_pointer_guard()`. fileciteturn4file0

## Ghi đè `__exit_funcs`

Thay vì ROP trên stack, script dùng chính vùng writer overlap để dựng fake chunk và ép allocator split remainder đúng vào `__exit_funcs`. Sau đó nó ghi một entry mới với:

- `fn = mangled(system)`
- `arg = "cat flag"`

Phần này nằm trong `final_overwrite()`. Cuối cùng script chọn menu `6`, chương trình thoát, glibc chạy exit handlers và gọi `system("cat flag")`. fileciteturn4file0

## Kết luận

Flow của bài là:

1. tạo overlap bằng bug trong custom allocator,
2. forge `Note` để có arbitrary read,
3. leak stack -> parse `auxv` -> lấy PIE,
4. leak `write@GOT` -> lấy libc,
5. recover `pointer_guard`,
6. overwrite `__exit_funcs` để `system("cat flag")` chạy khi exit.

Ưu điểm của hướng này là không cần stack smash hay ROP chain dài, chỉ cần leak đủ địa chỉ rồi dùng chính cơ chế exit của glibc để thực thi lệnh. fileciteturn4file0

# notebook

## Tóm tắt

Bài có bug trong allocator tự viết `Cage`. Khi một chunk được `free` và gộp ngược về phía trước, allocator cập nhật sai `priv_size` của chunk kế tiếp. Lỗi này tạo ra hai free chunk chồng lấn lên nhau. Từ overlap đó, ta ghi đè metadata `Note` của một `NoteBook` khác để biến chức năng `read note` thành arbitrary read.

Sau khi có arbitrary read:

1. scan stack từ xa
2. dump stack rồi parse `auxv` để lấy PIE base
3. leak `write@GOT` để có một địa chỉ trong libc
4. scan lùi về ELF header để lấy libc base ổn định, không phụ thuộc patch-level
5. đọc `__exit_funcs`, khôi phục `pointer_guard`
6. dùng fake free chunk để ghi đè con trỏ `__exit_funcs`
7. cho chương trình thoát để glibc gọi `system("cat flag")`

Flag remote:

```text
HCMUS-CTF{w0w_1_m4d3_th15_ch4ll3ng3_1n_my_b1rthd4y}
```

## Phân tích source

Menu:

```cpp
0:switch  1:write  2:read  3:erase  4:discard  5:tag  6:exit
```

Hai struct quan trọng:

```cpp
typedef struct Note
{
    uint64_t size;
    char *data;
} Note;

typedef struct NoteBook
{
    Note notes[48];
} NoteBook;
```

`read note` rất mạnh:

```cpp
write(1, n->data, n->size);
cout << "\n";
```

Nếu ghi đè được `size` và `data` của một `Note`, ta đọc được dữ liệu tại địa chỉ tùy ý.

## Root cause

Bug nằm trong `Cage::consolidate()`:

```cpp
Block *consolidate(Block *cur)
{
    Block *lo = cur, *hi = cur;
    uint64_t newsz   = SIZE(cur);
    uint64_t pred_sz = SIZE(cur);

    while (!is_base(lo) && !prev_inuse(lo))
    {
        pop_bin(prev_blk(lo));
        lo = prev_blk(lo);
        newsz += SIZE(lo);
    }
    ...
    lo->curr_size           = newsz;
    next_blk(lo)->priv_size = pred_sz;
```

`pred_sz` được giữ bằng `SIZE(cur)` ban đầu, trong khi sau vòng lặp phía trên thì chunk thật sự ở phía trước có thể đã bị merge lớn hơn rất nhiều.

Kịch bản lỗi:

1. `B` được free
2. `A` free tiếp và gộp thành `A+B`
3. `C` đứng ngay sau `B`
4. vì `C->priv_size` bị ghi sai nên khi free `C`, allocator tưởng free chunk phía trước chỉ là `B`
5. kết quả: vừa tồn tại free chunk `A+B`, vừa tồn tại free chunk `B+C`

Đó là overlap primitive chính.

## Tạo overlap ban đầu

Mình dùng đúng layout kinh điển của đề:

- `A`: request `0x170` -> chunk `0x180`
- `B`: request `0x170` -> chunk `0x180`
- `C`: request `0x2f0` -> chunk `0x300`
- `D`: request `0xf0` -> chunk `0x100` để chặn top consolidation

Thao tác:

1. `free(B)`
2. `free(A)`
3. `free(C)`

Sau đó:

1. `switch(book 1)` để allocator lấy `NoteBook` mới từ free chunk `B+C`
2. quay lại `book 0`
3. `write_note(slot 0, size 0x2f0)` để lấy free chunk `A+B`

Chunk writer mới của `book 0` đè lên phần đầu `notes[]` của `book 1`.

Vì `book 1` nằm trên chunk `B+C`, còn writer mới của `book 0` nằm trên `A+B`, nên vùng cuối của `A+B` chồng lên các `Note` đầu tiên của `book 1`.

## Biến overlap thành arbitrary read

Mỗi `Note` là:

```cpp
struct Note {
    uint64_t size;
    char *data;
};
```

Nếu forge:

- `size = 8`
- `data = addr`

thì `read note` sẽ leak 8 byte tại `addr`.

Trong script, writer của `book 0` được dùng để forge khoảng 23 `Note` đầu của `book 1`. Để tăng throughput khi scan remote, exploit lặp lại primitive này thành nhiều nhóm độc lập:

- mỗi nhóm chiếm 4 slot của `book 0`: `A/B/C/D`
- mỗi nhóm sinh ra 1 `book` phụ có 23 fake note để đọc
- tổng cộng dùng 10 nhóm -> 230 probe mỗi vòng

Nhờ vậy việc scan stack từ xa nhanh hơn nhiều.

## Scan stack từ remote

Ta không có `/proc/self/maps`, nên phải tìm stack bằng hành vi của `read`.

Ý tưởng:

1. forge rất nhiều slot với:
   - `size = 1`
   - `data = candidate_addr`
2. gọi `read note`
3. nếu `candidate_addr` readable, `write(1, ptr, 1)` in ra đúng 1 byte
4. nếu không readable, syscall `write` thất bại và chương trình chỉ in newline

Exploit scan vùng:

```text
0x7ffc00000000 .. 0x800000000000
```

với stride `0x20000`.

Khi gặp một hit đầu tiên, script refine lại quanh đó theo page `0x1000` trong cửa sổ:

```text
[hit - 0x40000, hit + 0x50000]
```

Rồi lấy dải page readable liên tiếp dài nhất làm stack mapping thật.

## Parse auxv để lấy PIE

Sau khi dump toàn bộ stack mapping, exploit tìm `auxv`.

Ta cần `AT_PHDR`:

```text
PIE base = AT_PHDR - e_phoff
```

Trong script, sau khi đoán được một `PIE base`, exploit verify lại bằng cách leak 4 byte đầu tại đó và kiểm tra magic:

```text
0x7f 45 4c 46
```

Nếu đúng ELF header thì nhận base.

## Leak libc base

Sau khi có PIE:

1. leak `write@GOT`
2. từ địa chỉ thực của `write`, scan ngược từng page cho đến khi gặp ELF header của libc

Điểm hay ở đây là bản solve cuối không còn phụ thuộc vào `write` offset cứng nữa. Ban đầu mình thử trừ offset trực tiếp, nhưng remote chạy `glibc 2.39` patch-level khác local nên bị lệch. Scan ngược về ELF base khiến bước này ổn định hơn.

## Khôi phục pointer_guard

glibc mã hóa function pointer trong `__exit_funcs` theo công thức:

```text
mangled = rol(real_fn ^ pointer_guard, 17)
```

Ta cần `pointer_guard` để forge callback mới.

Exploit đọc:

- con trỏ `__exit_funcs`
- `initial` list mà `__exit_funcs` đang trỏ tới

Rồi duyệt các entry. Entry của binary dễ nhận ra vì `arg` hoặc `dso_handle` nằm trong vùng PIE.

Với entry này, function thật là destructor của đối tượng global `cage`, tức:

```text
Cage::~Cage()
```

Từ đó:

```text
pointer_guard = ror(mangled, 17) ^ (pie + offset_of_Cage_dtor)
```

Trong binary này offset đó là `0x4a6c`.

## Ghi đè __exit_funcs

Phần cuối không đụng vào stack hay return address. Ta ghi thẳng vào danh sách exit handler của glibc.

### Ý tưởng

1. leak `books[0]`
2. leak con trỏ writer hiện tại của `book 0`
3. dùng chính writer chunk làm nơi đặt:
   - fake `exit_function_list`
   - chuỗi `"cat flag"`
   - fake free chunk header
4. forge một fake chunk đủ lớn
5. free fake chunk đó bằng cách dùng `book 1` đọc metadata giả
6. ép allocator split fake chunk sao cho remainder rơi đúng vào `__exit_funcs`
7. cấp phát remainder đó và ghi con trỏ `__exit_funcs = fake_list`
8. chọn `6` để thoát

### Vì sao cần 2 giai đoạn

Script dùng 2 payload:

1. payload đầu để tạo fake free chunk “an toàn”, có kích thước dừng trước một filler chunk thật
2. free fake chunk
3. payload thứ hai sửa lại fake chunk header thành kích thước rất lớn, để lần alloc tiếp theo split đúng vị trí `__exit_funcs`

Cách này giúp tránh crash sớm vì fake chunk ban đầu vẫn có next chunk hợp lệ.

### Fake exit list

Exploit dựng `fake_list` ngay trong writer chunk:

- `next = NULL`
- `idx = 1`
- entry 0:
  - `flavor = 4`
  - `fn = mangled(system)`
  - `arg = "cat flag"`
  - `dso_handle = 0`

Trong solve:

```text
fn = rol(system ^ pointer_guard, 17)
```

Khi chương trình thoát, glibc gọi:

```c
system("cat flag");
```

## Những điểm quan trọng khi exploit remote

### 1. Không nên phụ thuộc hoàn toàn vào offset `write`

Remote dùng `glibc 2.39` nhưng patch-level khác local. Nếu chỉ làm:

```text
libc_base = write_addr - libc.sym["write"]
```

thì rất dễ lệch.

Bản solve cuối sửa thành:

1. leak `write@GOT`
2. scan ngược từng page
3. tìm ELF header libc

### 2. pointer_guard phải lấy từ entry đúng

Ban đầu dễ nhầm entry destructor thuộc `libstdc++`. Entry ổn định nhất để suy ngược guard là entry thuộc chính binary, tức destructor của `cage`.

### 3. Scan stack phải đủ nhanh

Nếu mỗi vòng chỉ probe 23 địa chỉ thì remote khá chậm. Dùng nhiều nhóm overlap song song giúp giảm thời gian scan xuống mức chấp nhận được.

## Cấu trúc solve.py

File exploit: [solve.py](/d:/HCMUS%20CTF%202026/notebook/to_player/solve.py)

Các bước chính:

1. `setup_scan_groups()`
   - dựng 10 overlap group
2. `find_stack_anchor()`
   - scan coarse vùng stack
3. `refine_stack_mapping()`
   - refine theo page
4. `dump_stack()`
   - dump stack mapping
5. `find_auxv_and_pie()`
   - parse `AT_PHDR`
6. `find_elf_base()`
   - từ `write@GOT` scan ngược về ELF header libc
7. `recover_pointer_guard()`
   - đọc `__exit_funcs`
8. `final_overwrite()`
   - fake chunk + overwrite `__exit_funcs`
9. `exit`
   - lấy flag

## Cách chạy

```bash
python solve.py
```

Hoặc chỉ định host/port:

```bash
python solve.py --host chall.blackpinker.com --port 20767
```

## Kết luận

Điểm hay của bài này là:

- bug allocator không cho write primitive trực tiếp, nhưng đủ để tạo overlap
- overlap của notebook biến rất tự nhiên thành arbitrary read
- không cần ROP
- không cần stack smash
- đích cuối là `__exit_funcs`, một target rất gọn và sạch

Chain cuối cùng:

```text
allocator bug
-> overlap free chunks
-> forge Note metadata
-> arbitrary read
-> leak stack / PIE / libc
-> recover pointer_guard
-> overwrite __exit_funcs
-> system("cat flag")
```

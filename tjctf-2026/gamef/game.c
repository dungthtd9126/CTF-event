#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void game(char map[81])
{
    char input_log[64];
    int killCt = 0;
    int *kills = &killCt;
    int player_position = 40;
    int turn_cnt = 1;
    char *array_ptr = &input_log[63];
    int game_running = 1;
    *kills = 0;
    printf("%i", *kills);
    while (game_running) {
    for (int i = 0; i < 81; i++) // print map
    {
        if (i % 9 == 0) puts("");
        printf("%c ", map[i]);
    }
    char player_input[2] = "Hi";
    while ((!strchr("MA", player_input[0])) || (!strchr("NESW", player_input[1]))) // repeat until valid input
    { // player input getting
        printf("Enter (M)ove or (A)ttack, followed by direction (N)orth (E)ast (S)outh (W)est ");
        scanf("%c", &player_input[0]);
        scanf("%c", &player_input[1]);
        int c; while ((c = getchar()) != '\n' && c != EOF);
        *array_ptr = player_input[0];
        array_ptr -= sizeof(player_input[0]);
        *array_ptr = player_input[1];
        array_ptr -= sizeof(player_input[1]);
    }
    array_ptr += 2*sizeof(player_input[0]);
    puts("");
    if (player_input[0] == 'M') // handle movement
    {
        map[player_position] = '.';
        if (player_input[1] == 'E' && player_position % 9 != 8)
            player_position += 1;
        if (player_input[1] == 'S' && player_position < 72)
            player_position += 9;
        if (player_input[1] == 'W' && player_position % 9 != 0)
            player_position -= 1;
        if (player_input[1] == 'N' && player_position > 8)
            player_position -= 9;
        if (map[player_position] == 'E') {
            game_over(kills); 
            break; }
        else
            map[player_position] = '@';
    } 
    if (player_input[0] == 'A') // handle attack
    {
        int targeted_tile;
        if (player_input[1] == 'E')
            targeted_tile = player_position + 1;
        if (player_input[1] == 'S')
            targeted_tile = player_position + 9;
        if (player_input[1] == 'W')
            targeted_tile = player_position - 1;
        if (player_input[1] == 'N')
            targeted_tile = player_position - 9;
        if (map[targeted_tile] == 'E') // enemy in tile
        {
            map[targeted_tile] = '.';
            (*kills)++;
        }
    } 
    int enemy_positions[80];
    int enemy_arr_spot = 0;
    for (int i = 0; i < 81; i++) // enemy position finding
    {
        if (map[i] == 'E') {
            enemy_positions[enemy_arr_spot] = i;
            enemy_arr_spot++; }
    }
    if (enemy_arr_spot) {
    for (int i = 0; i < enemy_arr_spot; i++) // enemy movement
    {
        int target_move_pos;
        if (enemy_positions[i] > player_position)
        {
            if (enemy_positions[i] < player_position + 9 - player_position%9) // same line
                target_move_pos = enemy_positions[i] - 1;
            else
                target_move_pos = enemy_positions[i] - 9;
        }
        else
        {
            if (enemy_positions[i] > player_position - 1 - player_position%9) // same line
                target_move_pos = enemy_positions[i] + 1;
            else
                target_move_pos = enemy_positions[i] + 9;
        }
        if (map[target_move_pos] == '.')
        {
            map[target_move_pos] = 'E';
            map[enemy_positions[i]] = '.';
        }
        else if (map[target_move_pos] == '@')
        {
            game_over(kills);
            break;
        }
    } }
    if (turn_cnt % 2 == 0 || turn_cnt % 5 == 0) // enemy spawning
    {
        int rando = (turn_cnt * player_input[0] * player_input[1] + player_position) % 18;
        if (rando > 8) rando += 63;
        if (map[rando] == '.')
            map[rando] = 'E';
    }

    turn_cnt++;
}
}

int main()
{
    setbuf(stdout, NULL);
    char map[81];
    for (int i = 0; i < 81; i++)
    {
        map[i] = '.';
    }
    map[40] = '@';
    game(map);
    puts("");
    return 1;
}

void game_over(int *kills)
{
    puts("\nGame Over!");
    printf("You defeated %i enemies!\n", *kills);
    if (*kills == 1752526452)
    {
        int flagSize = 30;
        char flag[flagSize];
        FILE* file_ptr;
    
        file_ptr = fopen("./flag.txt", "r");
        if (file_ptr == NULL)
        {
            printf("Failed to get flag. Make sure you have a file titled flag.txt somewhere in this directory!");
        }
        else if(fgets(flag, flagSize, file_ptr) != NULL)
        {
            printf("So many foes have fallen before you. Take this flag as proof of your victory!\n %s \n", flag);
        }
    }
}

#include "bye-libc.h"

// Used for read/write
#define STDIN 0
#define STDOUT 1

// Used for menu
#define WRITE_NUM 1
#define ADD_NUM 2
#define SUB_NUM 3
#define MUL_NUM 4
#define DIV_NUM 5
#define PRINT_NUM 6
#define EXIT 7

// To make input/output easier
#define print(str) write(STDOUT, str, strlen(str))

// Prints menu
void print_menu() {
  print("\n\n1. Write Numbers\n");
  print("2. Add Numbers\n");
  print("3. Subtract Numbers\n");
  print("4. Multiply Numbers\n");
  print("5. Divide Numbers\n");
  print("6. Print Numbers\n");
  print("7. Exit\n\n");
  return;
}

// Input used for menu
int input_menu() {
  char input[16];
  
  print("Enter input: ");
  read(STDIN, input, 16);

  int choice = input[0] - '0';

  if (choice <= EXIT && choice >= 1) {
    return choice;
  }
  else {
    print("Invalid input! Try again. \n\n\n\n");
    return -1;
  }
}

// Takes in input as large as 3
int input_index() {
  char input[16];

  read(STDIN, input, 16);
  int choice = 0;
  
  // Add all digits in input
  for (int i = 0; i < 16; ++i) {
    if (input[i] >= '0' && input[i] <= '9') {
      // Increase digit and add next digit
      choice = 10*choice + (input[i]-'0');
    }
    else {
      break;
    }
  }

  if (choice <= 3 && choice >= -2) {
    return choice-1;
  }
  else {
    print("Invalid index!\n\n");
    return -1;
  }
}

// Takes in input for nums array
unsigned long input_num() {
  char input[64];

  read(STDIN, input, 64);
  unsigned long choice = 0;
  
  // Add all digits in input
  // Only check if input[i] = (0 -> 9) - If not, break the loop
  for (int i = 0; i < 64; ++i) {
    if (input[i] >= '0' && input[i] <= '9') {
      // Increase digit and add next digit
      choice = 10*choice + (input[i]-'0');
    }
    else {
      break;
    }
  }
  // only check input[0]
  if (input[0] >= '0' && input[0] <= '9') {
    return choice;
  }
  else {
    print("Not a valid number! 0 will be written instead.\n\n");
    return 0;
  }
}

// Converts long to string, for the purpose of printing
char* long_to_str(unsigned long num) {
  // Needs to be static so string is accessible after function return
  static char str[64];
  int i = 0;
  int len = 0;

  // If number = 0
  if (num == 0) { 
    str[0] = '0'; 
    str[1] = '\0'; 
    return str;
  }

  char tmp[64];
  while (num > 0) { 
    tmp[i++] = '0' + (num % 10); 
    num /= 10; 
  }
  while (i > 0) {
    str[len++] = tmp[--i];
  }
  str[len] = '\0';
  return str;
}

// Print statement used for expressions
void print_expression(unsigned long a, unsigned long b, char* expression) {
  print("\nResult of "); 
  print(long_to_str(a)); 
  print(expression); 
  print(long_to_str(b)); 
}

// Write value to nums array
void write_num(long* i) {
  print("\nSelect value to write: ");
  *i = input_num();
}


int _start() {
  int input;
  unsigned long nums[3] = {0};
  
  print("========================\n");
  print("Safe Calculator v1.0\n");
  print("========================");

  while (1) {
    print_menu();
    input = input_menu();
    if (input == -1) continue;

    int index = 0;
    int secondindex = 0;
    switch (input) {

    case WRITE_NUM:
      print("Select index to write to [1-3]: ");
      index = input_index();
      
      write_num(&nums[index]);
      break;

    case ADD_NUM:
      print("Select first index to add [1-3]: ");
      index = input_index();
      if (index == -1) continue;
      print("Select second index to add [1-3]: ");
      secondindex = input_index();
      if (secondindex == -1) continue;

      print_expression(nums[index], nums[secondindex], " + ");
      print(": ");
      print(long_to_str(nums[index] + nums[secondindex]));
      break;

    case SUB_NUM:
      print("Select first index to subtract [1-3]: ");
      index = input_index();
      if (index == -1) continue;
      print("Select second index to subtract [1-3]: ");
      secondindex = input_index();
      if (secondindex == -1) continue;

      print_expression(nums[index], nums[secondindex], " - ");
      print(": ");
      if (nums[index] >= nums[secondindex]) {
        print(long_to_str(nums[index] - nums[secondindex]));
      }
      else {
        // If result is negative
        print("-");
        print(long_to_str(nums[secondindex] - nums[index]));
      }
      break;

    case MUL_NUM:
      print("Select first index to multiply [1-3]: ");
      index = input_index();
      if (index == -1) continue;
      print("Select second index to multiply [1-3]: ");
      secondindex = input_index();
      if (secondindex == -1) continue;

      print_expression(nums[index], nums[secondindex], " * ");
      print(": ");
      print(long_to_str(nums[index] * nums[secondindex]));
      break;

    case DIV_NUM:
      print("Select first index to divide [1-3]: ");
      index = input_index();
      if (index == -1) continue;
      print("Select second index to divide [1-3]: ");
      secondindex = input_index();
      if (secondindex == -1) continue;

      print_expression(nums[index], nums[secondindex], " / ");
      print(": ");
      print(long_to_str(nums[index] / nums[secondindex]));
      print("\nRemainder: ");
      print(long_to_str(nums[index] % nums[secondindex]));
      break;

    case PRINT_NUM:
      print("Select index to read from [1-3]: ");
      index = input_index();
      if (index == -1) continue;
      print("\nValue written: ");
      print(long_to_str(nums[index]));
      break;

    case EXIT:
      exit(0);
    }

  }
  exit(0);
}


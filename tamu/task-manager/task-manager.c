#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define ADD_TASK 1
#define PRINT_TASK 2
#define DELETE_TASK 3
#define ADD_REMINDER 4
#define EXIT_TASK 5

// IGNORE THIS:
void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}


// struct for Tasks
typedef struct Tasks {
  char task[80];
  struct Tasks* next;
} Tasks;

// struct for Task Pointer
typedef struct {
  int sel;
  Tasks** head;
  char reminder[72];
} TaskHead;

// Size of task list
unsigned long long size = 0;


// Deletes last task
inline __attribute__((always_inline)) void cleanup(Tasks** tasks) {
  // If last entry, removal process requires two frees
  if (size == 1) {
    free((*tasks)->next);
    (*tasks)->next = NULL;
    free(*tasks);
    *tasks = NULL;
    return;
  }

  // Iterates until last task is reached
  Tasks* temp = *tasks;
  for (unsigned long long i = 1; i < size; ++i) {
    temp = temp->next;
  }

  // Freeing next pointer
  free(temp->next);
  temp->next = NULL;
  return;
}


// Prints all tasks
inline __attribute__((always_inline)) void print_tasks(Tasks* tasks) {
  // Do not print if no tasks exist
  if (size < 1) {
    puts("No tasks to print!\n");
    return;
  }

  // Printing all tasks:
  printf("Task #1: %s\n", tasks->task);
  Tasks* temp = tasks;
  for (unsigned long long i = 2; i <= size; ++i) {
    temp = temp->next;
    printf("Task #%lld: %s\n", i, temp->task);
  }
  puts("");
}


// Add a reminder
inline __attribute__((always_inline)) void add_reminder(TaskHead* task_pointer) {
  printf("Old reminder: %s\n", task_pointer->reminder);

  // Enter info for reminder
  printf("Enter reminder (max. 72 characters): ");
  read(0, task_pointer->reminder, 72);

  printf("Reminder you entered: %s\n", task_pointer->reminder);
  return;
}


// Creates new task
inline __attribute__((always_inline)) void create_tasks(Tasks** tasks) {
  Tasks* temp = NULL;

  // If no tasks exist, create Tasks struct
  if (*tasks == NULL) {
    *tasks = malloc(sizeof(Tasks));
    temp = *tasks;
    temp->next = malloc(sizeof(Tasks));
  }
  // Otherwise, create next task
  else {
    temp = *tasks;
    for (unsigned long long i = 1; i <= size; ++i) {
      temp = temp->next;
    }
    temp->next = malloc(sizeof(Tasks));
  }

  // Enter info for new task
  printf("Enter task (max. 80 characters): ");
  read(0, temp->task, 88);

  printf("Task you entered: %s\n", temp->task);
}


int main() {
  init();

  // Initializing variables
  Tasks* tasks = NULL;
  TaskHead* taskPointer = malloc(sizeof(TaskHead));
  taskPointer->head = &tasks;
  taskPointer->sel = 0;

  // Entering name
  char name[40] = "\0";
  printf("Enter your name (max. 40 characters): ");
  read(0, name, 40);

  printf("Welcome, %s!\n", name);
  puts("Welcome to Task Manager!\n");

  // Menu
  while (1) {
    if ((char)taskPointer->reminder != "\0") {
      printf("Reminder: %s\n", taskPointer->reminder);
    }
    puts("1. Add New Task");
    puts("2. Print All Tasks");
    puts("3. Delete Last Task");
    puts("4. Add Reminder");
    puts("5. Exit");

    printf("Enter your input: ");
    scanf("%d", &taskPointer->sel);
    printf("You selected: %d\n\n", taskPointer->sel);
    
    switch (taskPointer->sel) {
      case ADD_TASK:
        create_tasks(taskPointer->head);
        size += 1;
        break;
      case PRINT_TASK:
        puts("Printing all tasks in order:\n");
        print_tasks(tasks);
        break;
      case DELETE_TASK:
        // Break if no tasks left to remove
        if (size < 1) {
          puts("No task to remove!\n");
          break;
        }
        puts("Removing task...");

        // Deletes last task
        cleanup(&tasks);
        size -= 1;
        printf("Remaining tasks: %lld\n\n", size);
        break;
      case ADD_REMINDER:
        add_reminder(taskPointer);
        break;
      case EXIT_TASK:
        puts("Exiting.....");
        // Cleanup all tasks if exiting
        while (size > 0) {
          cleanup(&tasks);
          size -= 1;
        }
        free(taskPointer);
        return 0;
      default:
        puts("Invalid input! Try again.\n");
        break;
    }
  }
}


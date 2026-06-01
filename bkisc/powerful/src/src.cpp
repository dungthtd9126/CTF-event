#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <stack>
#include <algorithm>

using namespace std;

// --- Data Structures ---

class dfs_instance {
public:
    int num;
    vector<vector<int>> adj;

    dfs_instance(int n) {
        num = n;
        adj.assign(n + 1, vector<int>());
    }

    void addEdge(int u, int v) {
        // BUG 1: Out-of-Bounds (OOB) array access. No bounds checking.
        adj[u].push_back(v);
    }

    void dfs(uint64_t s, vector<long long>* visited, vector<int>* visit_order) {
        std::fill(visited->begin(), visited->end(), 0);
        visit_order->clear();
        std::stack<int> st;

        if (s > 0 && s <= this->num) {
            st.push(s);
        }

        while (!st.empty()) {
            int u = st.top();
            st.pop();

            if (u >= 0 && u <= this->num && (*visited)[u] == 0) {
                (*visited)[u] = 1;
                
                // ARBITRARY WRITE TARGET (via UAF)
                visit_order->push_back(u);

                for (int v : this->adj[u]) {
                    if (v > 0 && v <= this->num && (*visited)[v] == 0) {
                        st.push(v);
                    }
                }
            }
        }
    }
};

class Job {
public:
    int id;
    dfs_instance* instance;
    uint64_t source;
    atomic<bool> done;
    vector<long long> visited;
    vector<int> visit_order;

    Job(int id, dfs_instance* inst, uint64_t s) {
        this->id = id;
        this->instance = inst;
        this->source = s;
        this->done = false;
        this->visited.assign(inst->num + 1, 0);
    }
};

// --- Global Variables ---

vector<dfs_instance*> problems;
vector<Job*> jobs;
int dfsProblemNum = 0;
int jobNum = 0;

// --- Functions ---

void menu() {
    puts("\n--- Powerful DFS Menu ---");
    puts("1. Create new DFS problem");
    puts("2. Start DFS job (Background)");
    puts("3. View jobs board");
    puts("4. Delete completed job");
    puts("5. Exit");
    printf("> ");
}

void dfs_runner(Job* job) {
    job->instance->dfs(job->source, &job->visited, &job->visit_order);
    job->done = true; 
}

void create_problem() {
    int n, m, u, v, i;
    
    printf("Number of nodes: ");
    if (scanf("%d", &n) == 1) {
        if (n > 4096) {
            printf("n too big!");
            exit(-1);
        }
        
        dfs_instance* instance = new dfs_instance(n);
        problems.push_back(instance);
        
        printf("Number of edges: ");
        if (scanf("%d", &m) == 1) {
            for (i = 0; i < m; ++i) {
                printf("Edge %d (u v): ", i);
                if (scanf("%d %d", &u, &v) != 2) break;
                instance->addEdge(u, v);
            }
            printf("Problem %d created!\n", dfsProblemNum++);
        }
    }
}

void start_job() {
    int idx, s;
    Job* job; 
    
    printf("Problem index: ");
    if (scanf("%d", &idx) != 1 || idx < 0 || idx >= problems.size()) {
        puts("Invalid index!");
    } else {
        printf("Source node: ");
        if (scanf("%d", &s) == 1) {
            job = new Job(jobNum++, problems[idx], s);
            jobs.push_back(job);
            
            // BUG 2: Stack Use-After-Free / Thread Race Condition
            std::thread t((void (*)(Job*))dfs_runner, job);
            t.detach();
            
            printf("Job %d started!\n", job->id);
        }
    }
}

void view_jobs() {
    if (jobs.empty()) {
        puts("No jobs found.");
    } else {
        for (Job* job : jobs) {
            const char* status = job->done ? "Completed" : "Running";
            printf("Job %d: Status=%s, Nodes=%d, Source=%llu\n", 
                   job->id, status, job->instance->num, job->source);
                   
            if (job->done) {
                printf("  Visit Order: ");
                for (int node : job->visit_order) {
                    printf("%d ", node);
                }
                putchar('\n');
            }
        }
    }
}

void delete_job() {
    int idx;
    
    printf("Job index: ");
    if (scanf("%d", &idx) != 1 || idx < 0 || idx >= jobs.size()) {
        puts("Invalid index!");
    } else {
        Job* job = jobs[idx];
        if (!job->done) {
            puts("Job is still running!");
        } else {
            delete job;
            jobs.erase(jobs.begin() + idx);
            puts("Job deleted.");
        }
    }
}

int main(int argc, const char **argv, const char **envp) {
    setvbuf(stdout, NULL, _IONBF, 0); 
    
    int choice;
    while (true) {
        menu();
        if (scanf("%d", &choice) != 1) break;
        
        switch (choice) {
            case 1: create_problem(); break;
            case 2: start_job();      break;
            case 3: view_jobs();      break;
            case 4: delete_job();     break;
            case 5: return 0;
            default: puts("Invalid choice!"); break;
        }
    }
    return 0;
}
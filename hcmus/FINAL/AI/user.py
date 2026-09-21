#!/usr/bin/env python3
import os
import json
import requests
from typing import Dict, Any

# ANSI Color Codes for Rich Aesthetics
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Skip config file
CONFIG_FILE = ".client_config.json"

def show_endpoint_guide(server_url: str):
    base_url = server_url.rstrip("/")
    print(f"\n{Colors.BOLD}=== SERVER ENDPOINTS & USAGE ==={Colors.ENDC}")
    print(f"{Colors.BOLD}Authentication:{Colors.ENDC} include header {Colors.OKCYAN}X-Team-Token: <team_token>{Colors.ENDC}")

    print(f"\n{Colors.OKGREEN}GET  {base_url}/{Colors.ENDC}")
    print("  Public health check.")
    print("  Returns: status")

    print(f"\n{Colors.OKGREEN}GET  {base_url}/status{Colors.ENDC}")
    print("  Check team progress and remaining attempts.")
    print("  Returns: team_name, attempts_used, attempts_remaining, best_asr, best_avg_sim,")
    print("           solved, submissions_count, active_assignments_count")

    print(f"\n{Colors.OKGREEN}POST {base_url}/assignment{Colors.ENDC}")
    print("  Start one random image batch.")
    print("  Send:    X-Team-Token header")
    print("  Returns: assignment_id, expected_images, target_prompts, rules")
    print("  Use expected_images as the exact ZIP entry names for submission.")

    print(f"\n{Colors.OKGREEN}POST {base_url}/submit?assignment_id=<assignment_id>{Colors.ENDC}")
    print("  Submit one ZIP for the active assignment.")
    print("  Send:    X-Team-Token header")
    print("           multipart/form-data with file=<zip>")
    print("  Returns: status, batch_size, ASR, AvgSimDesc, success_count, attempts_used,")
    print("           attempts_remaining, passed, images responses, flag only if passed")

def load_config() -> Dict[str, Any]:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "server_url": "https://decent-normally-bedbug.ngrok-free.app/",
        "team_token": "ctf_token_team1_xyz",
        "assignment_id": "",
        "expected_images": [],
        "target_prompts": {},
    }

def save_config(config: Dict[str, Any]):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
        print(f"{Colors.OKGREEN}[+] Configuration saved to {CONFIG_FILE}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.WARNING}[!] Failed to save configuration: {e}{Colors.ENDC}")

def get_headers(token: str) -> Dict[str, str]:
    return {"X-Team-Token": token}

def check_status(url: str, token: str) -> bool:
    print(f"\n{Colors.OKCYAN}[*] Fetching status from {url}/status...{Colors.ENDC}")
    try:
        response = requests.get(f"{url}/status", headers=get_headers(token), timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"\n{Colors.BOLD}--- TEAM STATUS ---{Colors.ENDC}")
            print(f"{Colors.BOLD}Team Name:          {Colors.OKGREEN}{data.get('team_name')}{Colors.ENDC}")
            print(f"Attempts Used:      {data.get('attempts_used')}")
            print(f"Attempts Remaining: {Colors.OKCYAN}{data.get('attempts_remaining')}{Colors.ENDC}")
            print(f"Best ASR:           {data.get('best_asr', 0.0):.4f}")
            print(f"Best Avg Similarity:{data.get('best_avg_sim', 0.0):.4f}")
            print(f"Solved:             {Colors.OKGREEN if data.get('solved') else Colors.FAIL}{data.get('solved')}{Colors.ENDC}")
            print(f"Submissions count:  {data.get('submissions_count')}")
            print(f"Active Assignments: {data.get('active_assignments_count', 0)}")
            print(f"{Colors.BOLD}-------------------{Colors.ENDC}\n")
            return True
        elif response.status_code == 403:
            print(f"{Colors.FAIL}[-] Access Denied: Invalid X-Team-Token.{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[-] Error {response.status_code}: {response.text}{Colors.ENDC}")
    except requests.exceptions.RequestException as e:
        print(f"{Colors.FAIL}[-] Connection failed: {e}{Colors.ENDC}")
    return False

def request_assignment(url: str, token: str, config: Dict[str, Any]) -> bool:
    print(f"\n{Colors.OKCYAN}[*] Requesting random image assignment from {url}/assignment (Starting Game)...{Colors.ENDC}")
    try:
        response = requests.post(f"{url}/assignment", headers=get_headers(token), timeout=30)
        if response.status_code != 200:
            print(f"{Colors.FAIL}[-] Assignment request failed ({response.status_code}): {response.text}{Colors.ENDC}")
            return False

        data = response.json()
        config["assignment_id"] = data.get("assignment_id", "")
        config["expected_images"] = data.get("expected_images", [])
        config["target_prompts"] = data.get("target_prompts", {})
        save_config(config)

        print(f"{Colors.OKGREEN}[+] Assignment/Game started: {config['assignment_id']}{Colors.ENDC}")
        print(f"Expected images: {len(config['expected_images'])}")
        if config["expected_images"]:
            print(f"\n{Colors.BOLD}Expected image names and target prompts:{Colors.ENDC}")
            for image_name in config["expected_images"]:
                print(image_name)
                target_prompt = config["target_prompts"].get(image_name)
                if target_prompt:
                    print(f"  target: {target_prompt}")
        
        rules = data.get("rules", {})
        if rules:
            print(f"Perturbation Limit: {rules.get('perturbation_must_be_within_epsilon')}")
            print(f"Remaining Submissions:      {rules.get('remaining_submissions')}")
            print(f"ASR Pass Threshold:         >= {rules.get('pass_threshold_asr')}")
            print(f"AvgSimDesc Pass Threshold:      >= {rules.get('pass_threshold_avg_sim_desc')}")
            print(f"{Colors.BOLD}--------------------------{Colors.ENDC}\n")
        return True
    except requests.exceptions.RequestException as e:
        print(f"{Colors.FAIL}[-] Connection failed: {e}{Colors.ENDC}")
    return False

def submit_challenge(url: str, token: str, zip_path: str, assignment_id: str):
    if not os.path.exists(zip_path):
        print(f"{Colors.FAIL}[-] File not found: {zip_path}{Colors.ENDC}")
        return
    if not assignment_id:
        print(f"{Colors.FAIL}[-] No assignment_id configured. Request an assignment first.{Colors.ENDC}")
        return

    print(f"\n{Colors.OKCYAN}[*] Submitting {zip_path} to {url}/submit with assignment {assignment_id}...{Colors.ENDC}")
    print(f"{Colors.WARNING}[*] Note: VLM API evaluation runs in the background. Please wait...{Colors.ENDC}")
    
    try:
        with open(zip_path, "rb") as f:
            files = {"file": (os.path.basename(zip_path), f, "application/zip")}
            response = requests.post(
                f"{url}/submit",
                headers=get_headers(token),
                params={"assignment_id": assignment_id},
                files=files,
                timeout=300
            )
            
        if response.status_code == 200:
            data = response.json()
            print(f"\n{Colors.OKGREEN}{Colors.BOLD}[+] Submission COMPLETED!{Colors.ENDC}")
            print(f"Batch Size:         {data.get('batch_size')}")
            print(f"ASR:                {Colors.BOLD}{data.get('ASR', 0.0):.4f}{Colors.ENDC}")
            print(f"AvgSimDesc:         {Colors.BOLD}{data.get('AvgSimDesc', data.get('AvgSim', 0.0)):.4f}{Colors.ENDC}")
            print(f"Success Count:      {data.get('success_count')}")
            print(f"Attempts Used:      {data.get('attempts_used')}")
            print(f"Attempts Remaining: {data.get('attempts_remaining')}")
            
            passed = data.get("passed", False)
            passed_color = Colors.OKGREEN if passed else Colors.FAIL
            print(f"Passed:             {passed_color}{passed}{Colors.ENDC}")
            
            if passed:
                print(f"\n{Colors.HEADER}{Colors.BOLD}[!!!] FLAG: {data.get('flag')}{Colors.ENDC}\n")
        else:
            print(f"{Colors.FAIL}[-] Submission Failed ({response.status_code}): {response.text}{Colors.ENDC}")
    except requests.exceptions.RequestException as e:
        print(f"{Colors.FAIL}[-] Connection failed during submission: {e}{Colors.ENDC}")

def main():
    config = load_config()
    
    server_url = config.get("server_url", "https://decent-normally-bedbug.ngrok-free.app/")
    team_token = config.get("team_token", "ctf_token_team1_xyz")
    assignment_id = config.get("assignment_id", "")
    
    # Allow overriding via environment variables
    server_url = os.environ.get("CHALLENGE_URL", server_url)
    team_token = os.environ.get("TEAM_TOKEN", team_token)
    
    print(f"Current Settings:")
    print(f"  Server URL: {Colors.BOLD}{server_url}{Colors.ENDC}")
    print(f"  Team Token: {Colors.BOLD}{team_token}{Colors.ENDC}")
    print(f"  Assignment: {Colors.BOLD}{assignment_id or 'none'}{Colors.ENDC}")
    show_endpoint_guide(server_url)
    
    while True:
        print(f"\n{Colors.BOLD}=== MENU ==={Colors.ENDC}")
        print("1. Check Team Status & Attempts")
        print("2. Start Game / Request Image Assignment")
        print("3. Submit ZIP")
        print("4. Show Server Endpoints & Usage")
        print("5. Edit Server URL & Team Token")
        print("6. Exit")
        
        try:
            choice = input(f"\nEnter choice (1-6): {Colors.OKCYAN}").strip()
            print(Colors.ENDC, end="")
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Colors.OKBLUE}[*] Goodbye!{Colors.ENDC}")
            break
            
        if choice == "1":
            check_status(server_url, team_token)
        elif choice == "2":
            if request_assignment(server_url, team_token, config):
                assignment_id = config.get("assignment_id", "")
        elif choice == "3":
            zip_path = input("Enter path to submission ZIP (default: test_submission.zip): ").strip()
            if not zip_path:
                zip_path = "test_submission.zip"
            submit_challenge(server_url, team_token, zip_path, assignment_id)
        elif choice == "4":
            show_endpoint_guide(server_url)
        elif choice == "5":
            new_url = input(f"Enter server URL (current: {server_url}): ").strip()
            new_token = input(f"Enter team token (current: {team_token}): ").strip()
            
            if new_url:
                server_url = new_url
            if new_token:
                team_token = new_token
                
            config["server_url"] = server_url
            config["team_token"] = team_token
            save_config(config)
        elif choice == "6":
            print(f"{Colors.OKBLUE}[*] Goodbye!{Colors.ENDC}")
            break
        else:
            print(f"{Colors.FAIL}[-] Invalid choice. Please select 1-6.{Colors.ENDC}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import numpy as np
import torch
from pwn import *

# --- Connection Settings ---
HOST = "7rx2mxuw6kjfrw5snshs.a6.chal-kalmarc.tf"
PORT = 1337
D_IN = 784  # Standard for image-based challenges (28x28), adjust if needed

def query_oracle(x_array):
    """Sends input and parses the float output from the server."""
    try:
        # Use 'ssl=True' for the --ssl flag in the challenge description
        r = remote(HOST, PORT, ssl=True, level='error')
        
        # Convert array to space-separated string
        payload = " ".join(map(str, x_array))
        r.sendline(payload.encode())
        
        # Read the result (adjust if the server has a prefix like 'Result: ')
        response = r.recvline().decode().strip()
        r.close()
        return float(response)
    except Exception as e:
        return 0.0

def main():
    print("[*] Starting extraction on 7rx2mxuw6kjfrw5snshs.a6.chal-kalmarc.tf")
    
    extracted_w = []
    extracted_b = []
    
    # We probe the 'j' values directly. 
    # The viewer script says: W1[j] * 0.5 + b1[j] = 0.001 * j
    # This means the neurons are already sorted by bias!
    
    print("[*] Reconstructing weights row by row...")
    
    for j in range(128):
        # We want to isolate the j-th row. 
        # We can approximate the weight by checking the gradient at x=0.5
        # Since it's a ReLU network, f(x) = sum(ReLU(w*x + b))
        
        # Create a small perturbation to see how the output changes for this specific index
        x_base = np.full(D_IN, 0.5)
        eps = 0.001
        
        row_w = np.zeros(D_IN)
        base_val = query_oracle(x_base)
        
        # This is the 'slow' way, but most reliable for a first pass:
        # We calculate the partial derivative for each input dimension
        for i in range(D_IN):
            x_plus = x_base.copy()
            x_plus[i] += eps
            plus_val = query_oracle(x_plus)
            row_w[i] = (plus_val - base_val) / eps
            
        # For the bias, we use the identity from viewer.py
        # W1[j] * 0.5 + b1[j] = 0.001 * j
        bias = (0.001 * j) - np.dot(row_w, np.full(D_IN, 0.5))
        
        extracted_w.append(row_w)
        extracted_b.append(bias)
        
        if j % 10 == 0:
            print(f"[+] Processed {j}/128 rows...")

    # --- Save to model.pt ---
    state_dict = {
        "fc1.weight": torch.tensor(np.array(extracted_w), dtype=torch.float32),
        "fc1.bias": torch.tensor(np.array(extracted_b), dtype=torch.float32)
    }
    torch.save(state_dict, "model.pt")
    print("\n[!] Extraction complete! Saved as model.pt")
    print("[!] Now run: python viewer.py model.pt")

if __name__ == "__main__":
    main()
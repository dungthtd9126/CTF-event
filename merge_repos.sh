#!/bin/bash

# 1. Set your GitHub username
USER="dungthtd9126"

# 2. Set the default branch of the old repos (change to 'master' if needed)
BRANCH="main"

# 3. List the names of the repositories you want to merge here
REPOS=(
    "Lac-CTF"
    "Bsides"
)

# Loop through each repository and automate the subtree merge
for REPO in "${REPOS[@]}"; do
  echo -e "\n🚀 Starting merge for: $REPO"
  
  # Construct the URL and add the remote
  URL="https://github.com/$USER/$REPO.git"
  git remote add "$REPO" "$URL"
  
  # Add the subtree into a folder with the same name as the repo
  git subtree add --prefix "$REPO/" "$REPO" "$BRANCH"
  
  echo "✅ $REPO merged successfully!"
done
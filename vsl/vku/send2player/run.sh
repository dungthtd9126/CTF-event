#!/bin/bash

echo -n "[Setup] Please enter your secret key (max 100 chars): "
read -n 100 USER_SECRET
echo ""

export "KEY_$$"="$USER_SECRET"
echo "Setup complete for \"KEY_$$\""

exec ./vku
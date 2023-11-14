#!/bin/bash

directory="./challenges"


for file in "$directory"/*; do
    if [ -f "$file" ]; then
        echo "Processing file: $file"

        log_filename=$(echo $file | cut -d "/" -f 3)

        if [ -f "./logs/$log_filename.txt" ]; then
            echo "Skip"
            continue
        fi

        timeout 120 python3 bof_aeg.py $file >>  ./logs/$log_filename.txt
        
        # Pause for user input after each round
        # read -p "Press Enter to continue..."
    fi
done


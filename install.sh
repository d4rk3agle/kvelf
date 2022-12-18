#!/usr/bin/bash
gcc -O3 ./src/*.c -o ./kvelf
mv ./kvelf /usr/local/bin
rm -rf ./kvelf
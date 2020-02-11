#!/bin/bash
if [ "$1" == "/bin/bash" ]; then
    bash
else
    pip3 install --editable .
    punch-q $@
fi

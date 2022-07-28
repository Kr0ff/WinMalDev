#!/usr/bin/env python3

import sys


if len(sys.argv) < 2:
    print("[*] Usage: ./program.py \"VirtualAlloc\"")
    sys.exit(0)

_PROCNAME = sys.argv[1]

def toArray(PROCNAME):
    initialise = "char str%s[] = { " % (_PROCNAME)

    fPROCNAME = ''

    for l in PROCNAME:
        fPROCNAME = '\'' + '\',\''.join(PROCNAME) + '\''

    _outFinal = initialise + fPROCNAME + ", 0x0};"  
    return _outFinal

print(toArray(_PROCNAME))

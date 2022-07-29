#!/usr/bin/env python3

import sys

if len(sys.argv) < 2:
    print("[*] Usage: ./program.py \"VirtualAlloc\"")
    sys.exit(0)

_PROCNAME = sys.argv[1]

def toArray(PROCNAME):
    PROCNAME_HAS_DOT = PROCNAME
    PROCNAME_NO_DOT = ""
    
    if PROCNAME_HAS_DOT.find("."):
        PROCNAME_NO_DOT = PROCNAME_HAS_DOT.replace(".", "")
    
    initialise = "char str%s[]" % PROCNAME_NO_DOT + " = { "

    fPROCNAME = ''

    for l in PROCNAME:
        fPROCNAME = '\'' + '\',\''.join(PROCNAME) + '\''

    _outFinal = initialise + fPROCNAME + ", 0x0};"  
    return _outFinal

print(toArray(_PROCNAME))

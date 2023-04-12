#!/bin/python
# -*- coding: utf-8 -*-
import json
import re
import traceback
from pathlib import Path

class Evocatio:

    def __init__(self,maxDepth = 6,outputFile=Path("evocatio.loot.json")):
        self._maxDepth = maxDepth
        self._objects = []
        self._outputFD = outputFile
        self.levitasDict = lambda objects: [ d[obj] for d in objects for obj in d ]
        self.levitasList = lambda objects: [ obj for l in objects for obj in l ]

    def evocatio(self,root,label,lvl=0,keys=[]):
        try:            
            if hasattr(root,"items"):
                for k,v in root.items():
                    try:
                        if keys and k in keys:
                            self._objects.append({f"{label}.{k}":v})
                        if (hasattr(v,"items") or hasattr(v,"index")) and lvl <= self._maxDepth:
                            self.evocatio(v,f"{label}.{k}",lvl+1,keys)
                    except:
                        print(f"[!] {traceback.format_exc()}")
            else:
                if hasattr(root,"index"):
                    for idx,element in enumerate(root):
                        try:
                            if lvl <= self._maxDepth:
                                self.evocatio(element,f"{label}.{idx}",lvl+1,keys)
                        except:
                            print(f"[!] {traceback.format_exc()}")
                else:
                    print(f"[!] root object {root} is of type {type(root)}. update method for this type.")
        except:
            print(f"[x] {traceback.format_exc()}")
        return self._objects

    def readJSON(self,_delim="\n",fd=None):
        data = []
        if not fd:
            return data
        if not _delim:
            _delim = "\n"
        try:
            if not isinstance(fd,Path):
                fd = Path(fd)
            if fd.exists() and fd.is_file():
                try:
                    data = json.loads(fd.read_text())
                except:
                    textArray = fd.read_text().split(_delim)
                    textJSONString = json.dumps(textArray)
                    data = json.loads(textJSONString)
        except:
            print(f"[x] {traceback.format_exc()}")
        return data

    def reset(self):
        try:
            print(f"[*] Resetting objects list")
            self._objects.clear()
        except:
            print(f"[x] {traceback.format_exc()}")

    def setMaxDepth(self,depth):
        self._maxDepth = depth

    def show(self):
        try:
            print(f"[*] Objects:\n")
            print(json.dumps(self._objects,indent=4))
        except:
            print(f"[x] {traceback.format_exc()}")

    def write(self,file=None):
        try:
            if file:
                if not isinstance(file,Path):
                    file = Path(file)
                file.write_text(json.dumps(self._objects,indent=3))
            else:
                self._outputFD.write_text(json.dumps(self._objects,indent=3))
        except:
            print(f"[x] {traceback.format_exc()}")

cl /AL /Fosym16.obj /c /Zi symdump.c
link sym16 /MAP /LINE;
mapsym /N sym16.map

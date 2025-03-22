import sys
a=sys.argv
open(a[2],'wb').write(('const unsigned char '+a[3]+'[] = {'+','.join([hex(b) for b in open(a[1],'rb').read()])+'};').encode('utf-8'))
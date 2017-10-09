
import sys
import math
import numpy as np
from collections import namedtuple
from sets import Set
from scapy.all import *

# Uso:
# python nombre_script archivo_pcap
#
# ej (script nombrado como analizar_fuente.py):
# python analizar_fuente.py captura.pcap

#Logaritmo en base 2 de x
def log_2(x):
	return math.log(x) / math.log(2.0)

# Funcion para imprimir tablas en consola, sacada de aca:
# https://stackoverflow.com/questions/5909873/how-can-i-pretty-print-ascii-tables-with-python
def pprinttable(rows):
  if len(rows) > 1:
    headers = rows[0]._fields
    lens = []
    for i in range(len(rows[0])):
      lens.append(len(max([x[i] for x in rows] + [headers[i]],key=lambda x:len(str(x)))))
    formats = []
    hformats = []
    for i in range(len(rows[0])):
      if isinstance(rows[0][i], int):
        formats.append("%%%dd" % lens[i])
      else:
        formats.append("%%-%ds" % lens[i])
      hformats.append("%%-%ds" % lens[i])
    pattern = " | ".join(formats)
    hpattern = " | ".join(hformats)
    separator = "-+-".join(['-' * n for n in lens])
    print hpattern % tuple(headers)
    print separator
    _u = lambda t: t.decode('UTF-8', 'replace') if isinstance(t, str) else t
    for line in rows:
        print pattern % tuple(_u(t) for t in line)
  elif len(rows) == 1:
    row = rows[0]
    hwidth = len(max(row._fields,key=lambda x: len(x)))
    for i in range(len(row)):
      print "%*s = %s" % (hwidth,row._fields[i],row[i])



if __name__ == "__main__":

	print "Leyendo archivo..."
	packets = rdpcap(sys.argv[1])
	print "archivo leido. Procesando..."

	simbolos = dict()
	total_paquetes = 0

	for p in packets:
		total_paquetes += 1

		proto = p.getlayer(1).name
		cast = "unicast"
		if p.dst == "ff:ff:ff:ff:ff:ff":
			cast = "broadcast"

		s = (cast, proto) 
		if s in simbolos:
			simbolos[s] += 1
		else:
			simbolos[s] = 1

	tabla = list()
	Row = namedtuple("Row", ["simbolo", "probabilidad", "informacion"])
	entropia_muestral = 0

	for s in simbolos:
		proba_s = float(simbolos[s])/total_paquetes 
		info_s  = (-1)*log_2(proba_s)
		tabla.append(Row(str(s), str(proba_s*100) + " %", str(info_s) + " bits")) 
		entropia_muestral += proba_s*info_s

	print "" #dejar un espacio en blanco para que se vea mejor la tabla
	pprinttable(tabla)

	entropia_maxima = log_2(len(tabla))

	print ""
	print "entropia muestral: {0}".format(entropia_muestral)
	print "entropia maxima:   {0}".format(entropia_maxima)




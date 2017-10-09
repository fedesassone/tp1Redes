
import sys
import math
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

	tabla = dict()
	for s in simbolos:
		tabla[s] = float(simbolos[s])/total_paquetes

	#ahora, tabla contiene los simbolos con su respectiva probabilidad

	#entropia muestral
	entropia_muestral = 0
	for p in tabla:
		entropia_muestral += tabla[p]*(-1)*log_2(tabla[p])

	entropia_maxima = log_2(len(tabla))

	print "############ Simbolos: #############"
	print tabla
	
	print "############ entropia: #############"
	print "entropia muestral: {0}".format(entropia_muestral)
	print "entropia maxima:   {0}".format(entropia_maxima)




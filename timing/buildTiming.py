#!/usr/bin/python
#Source: https://github.com/GDSSecurity/mangers-oracle

import math, os, sys
from time import time
from subprocess import Popen, PIPE

def modpow(base, exponent, modulus):
        result = 1
        while exponent > 0:
                if exponent & 1 == 1:
                        result = (result * base) % modulus
                exponent = exponent >> 1
                base = (base * base) % modulus
        return result
def timeSend(f):
	half = modpow(f, e, n)
	whole = (half * c) % n
	str = hex(whole)[2:-1]
	
	start = time()
	p = Popen(["./decrypt", str], stdout=PIPE)
	output = p.communicate()[0]
	stop = time()
	return stop - start, output
	
################################################################################
def buildTiming(n, e, c):
	records = {}
	for trials in range(1, 1000):
		for i in range(1, 20):
			if trials == 1: records[i] = []
			
			f1 = pow(2, i)
			time, output = timeSend(f1)
			records[i].append(time)
			#print time, lessThanB(output), i
	for i in range(1,20):
		f = open('trials.' + str(i), 'w')
		for l in records[i]:
			f.write(str(l)+"\n")

################################################################################
################################################################################
if __name__ == "__main__":
	n = 157864837766412470414898605682479126709913814457720048403886101369805832566211909035448137352055018381169566146003377316475222611235116218157405481257064897859932106980034542393008803178451117972197473517842606346821132572405276305083616404614783032204836434549683833460267309649602683257403191134393810723409
	e = 0x10001
	c = int('5033692c41c8a1bdc2c78eadffc47da73470b2d25c9dc0ce2c0d0282f0d5f845163ab6f2f296540c1a1090d826648e12644945ab922a125bb9c67f8caaef6b4abe06b92d3365075fbb5d8f19574ddb5ee80c0166303702bbba249851836a58c3baf23f895f9a16e5b15f2a698be1e3efb74d5c5c4fddc188835a16cf7c9c132c', 16)
	p = int('2ea4875381beb0f84818ce1c4df72574f194f7abefe9601b21da092f484fa886ff0de66edf8babd4bd5b35dfdb0e642382947270a8f197e3cbaaa37cb8f7007f4604794a51c3bd65f8d17bfad9e699726ff9f61b99762d130777872eb4e9f1532cf3bfbfc3d2ad5d8d4582cc90a2e59915c462967b19965f77225447ce660d', 16)

	buildTiming(n, e, c)

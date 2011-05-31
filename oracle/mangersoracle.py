#!/usr/bin/python
#Source: https://github.com/GDSSecurity/mangers-oracle

import math, os, sys
from time import time
from optparse import OptionParser
from fractions import gcd
from decimal import *
from subprocess import Popen, PIPE
from hashlib import sha1
from Crypto.Util.number import long_to_bytes

def _strxor(s1, s2):
	# Not mine.  From hmac.py
	return "".join(map(lambda x, y: chr(ord(x) ^ ord(y)), s1, s2))
def modpow(base, exponent, modulus):
	result = 1
	while exponent > 0:
		if exponent & 1 == 1:
			result = (result * base) % modulus
		exponent = exponent >> 1
		base = (base * base) % modulus
	return result
def pprint(n, places=20):
	n = str(int(n))
	if len(n) > places:
		return n[0:places] + "...(" + str(len(n)) + ")"
	else:
		return n
def lessThanB(line):
	#Encoding Error indicates y < B
	return 'Encoding problem' in line
def greaterThanB(line):
	#Integer to Octets Failute (e.g. frame[0] or Invalid Obj) indicates y >= B
	return 'Missing item in object' in line
def encodeAndSend(f):
	half = modpow(f, e, n)
	whole = (half * c) % n
	str = hex(whole)[2:-1]
	
	p = Popen(["./decrypt", str], stdout=PIPE)
	output = p.communicate()[0]
	return output

################################################################################
# Stage 1	
def stage1(k, B, options, cheatingPlaintext=None):
	for i in range(1, 130):
		f1 = pow(2, i)
		if options.verbose:
			print "\tf1=", pprint(f1)
			if options.cheat: print "\t\tf1*m=", pprint(f1*cheatingPlaintext)
		answer = encodeAndSend(f1)
		if lessThanB(answer):
			if options.verbose: print "\t\tf1*m E [0, B): 0", "-", pprint(B)
			continue
		elif greaterThanB(answer):
			if options.verbose: print "\t\tf1*m E [B, 2B):", pprint(B), "-", pprint(2*B)
			break
		else:
			print "Unexpected return: ", answer
			exit(1)
	return f1

################################################################################
# Stage 2
def stage2(k, B, f1, options, cheatingPlaintext=None):
	f2 = int(math.floor((n + B) / B) * (f1 / 2))
	answer = encodeAndSend(f2)
	if options.verbose: 
		print "\tf2=", pprint(f2)
		if options.cheat: print "\t\tf2*m=", pprint(f2*cheatingPlaintext)
		print "\t\tf2*m E [n/2, n+B):", pprint(n/2), "-", pprint(n+B)
	iterations = 0
	while greaterThanB(answer) and iterations < k:
		f2 = f2 + (f1 / 2)
		answer = encodeAndSend(f2)
		if options.verbose: print "\tf2=", pprint(f2)
		if greaterThanB(answer):
			if options.verbose:
				if options.cheat: print "\t\tf2*m=", pprint(f2*cheatingPlaintext)
				print "\t\tf2*m E [n/2, n):", pprint(n/2), "-", pprint(n)
		else:
			if options.verbose:
				print "\t\tStopping..."
				if options.cheat: print "\t\tf2*m=", pprint(f2*cheatingPlaintext)
				print "\t\tf2*m E [n, n+B):", pprint(n), "-", pprint(n+B)
		iterations += 1

	if greaterThanB(answer):
		print "Stopped phase 2 after", iterations, "iterations - something's wrong"
		exit(1)
	elif not lessThanB(answer):
		print "Unexpected return: ", answer
		exit(1)
	return f2

################################################################################
# Stage 3
# The numbers we work with in this stage are so large we have to switch to the 
#  Decimal class and up the precision considerably.  This precision actually 
#  isn't enough for numbers we generate towards the end (in i*n) but it works 
#  anyway.
def stage3(k, Bd, f2, options, cheatingPlaintext=None):
	getcontext().prec=350
	mmin = Decimal(n / f2).to_integral_value(rounding=ROUND_CEILING)
	mmax = Decimal((n + Bd) / f2).to_integral_value(rounding=ROUND_FLOOR)

	f3 = f2
	oldf3 = -1
	iterations = 0
	iteratestop = 3500
	difference1 = difference2 = 1

	print "Beginning phase 3..."
	while oldf3 != f3 and mmin < mmax and iterations < iteratestop and (not options.cheat or (difference1 > 0 and difference2 > 0)):
		ftmp = Decimal((2*Bd) / (mmax-mmin)).to_integral_value(rounding=ROUND_FLOOR)
		i =  Decimal(ftmp * mmin / n).to_integral_value(rounding=ROUND_CEILING)
		oldf3 = f3
		f3 = Decimal((i * n) / mmin).to_integral_value(rounding=ROUND_CEILING)
		
		if options.cheat:
			difference1 = mmax - cheatingPlaintext
			difference2 = cheatingPlaintext - mmin
		difference = float(mmax-mmin)
		
		if not options.verbose:
			sys.stdout.write('Difference: ' + str(difference) + '               \r')
		else:
			#This if/else shows you how close you are to completion
			if options.cheat:
				print "\tmmin to p=", pprint(difference2)
				print "\tpd to mmax=", pprint(difference1)
			else:
				print "\tmmax to mmax=", pprint(difference)
			print "\tmmin=", pprint(mmin)
			print "\tmmax=", pprint(mmax)
			print
			print "\ti=", pprint(i)
			print "\tf3=", pprint(f3)
			if options.cheat: print "\tf3*m=", pprint(f3 * cheatingPlaintext)
			print "\tf3*m E [in, in+2B):", pprint(i*n), "-", pprint(i*n + 2*Bd)
		
		if f3 == 0: break
		
		answer = encodeAndSend(int(f3))
		if greaterThanB(answer):
			mmin = Decimal((i*n +Bd) / f3).to_integral_value(rounding=ROUND_CEILING)
			if options.verbose:
				print "\tGreater: new mmin."
				print "\tf3*m E [in +B, in +2B):", pprint(i*n + Bd),"-", pprint(i*n + 2*Bd)
		elif lessThanB(answer):
			mmax = Decimal((i*n +Bd) / f3).to_integral_value(rounding=ROUND_FLOOR)
			if options.verbose:
				print "\tLess: new mmax."
				print "\tf3*m E [in, in + B):", pprint(i*n), "-", pprint(i*n + Bd)
		else:
			print "Unexpected return: ", answer
			exit(1)
			
		iterations += 1
		
	if iterations >= iteratestop:
		print "Stopped phase 3 after ", iterations, "iterations - something's wrong"
		exit(1)
	elif f3 == 0:
		print "F3 was zero, something's wrong"
		exit(1)
	elif mmin > mmax:
		print "mmin > mmax, at", iterations, "iterations - something's wrong"
		print "\tmmin", pprint(mmin)
		print "\tmmax", pprint(mmax)
		exit(1)
	elif options.cheat and difference1 < 0 or difference2 < 0:
                print "plaintext no longer fits between the range."
                exit(1)

	return mmin

################################################################################
# Code from https://bugs.launchpad.net/pycrypto/+bug/328027 by Ryan Kelly

# We assume/hope they used the sha-1 hash function, although it's possible to 
#  use others.  
def unpad(k, foundPlaintext):
	hashFunction = sha1

	def mgf(mgfSeed,maskLen,hashFunction):
		maskLen = int(maskLen)
		hLen = hashFunction().digest_size
		if maskLen > 2**32 * hLen:
			raise ValueError("mask too long")
		T = ""
		for counter in range(int(math.ceil(maskLen / (hLen*1.0)))):
			C = long_to_bytes(counter)
			C = ('\x00'*(4 - len(C))) + C
			assert len(C) == 4, "counter was too big"
			T += hashFunction(mgfSeed + C).digest()
		assert len(T) >= maskLen, "generated mask was too short"
		return T[:maskLen]

	label = "" #We hope they didn't use a label, but it's not unusable if they did
	lHash = hashFunction(label).digest()
	hLen = len(lHash)

	plaintextBytes = ""
	destruction = int(foundPlaintext)
	while destruction > 0:
		plaintextBytes = chr(destruction % 256) + plaintextBytes
		destruction = destruction >> 8

	maskedSeed = plaintextBytes[ : hLen]
	maskedDB = plaintextBytes[hLen : ]

	seedMask = mgf(maskedDB, hLen, hashFunction)
	seed = _strxor(maskedSeed, seedMask)
	dbMask = mgf(seed, k - hLen - 1, hashFunction)
	DB = _strxor(maskedDB, dbMask)

	lHash1 = DB[:hLen]
	x01pos = hLen
	while x01pos < len(DB) and DB[x01pos] != "\x01":
		x01pos += 1
	PS = DB[hLen:x01pos]
	M = DB[x01pos+1:]

	if x01pos == len(DB):  # No \x01 byte
		print "Something's wrong, the 0x01 byte was not present."
		exit(1)
	if lHash1 != lHash:    # Mismatched label hash
		print "It appears they used a non-blank label.  This shouldn't matter..."
	return M

################################################################################
def mangersOracle(n, e, c, options, cheatingPlaintext=None):
	k = Decimal(str(math.log(n, 256))).to_integral_value(rounding=ROUND_CEILING)
	#k = math.ceil(math.log(n, 256))
	B = getcontext().power(Decimal(2), Decimal(8*(k-1)))
	#B = pow(2, 8*(k-1))
	#Bd = Decimal(str(B))

	if 2*B >= n:
		print "Obscure, unhandled case: 2B >= n"
		sys.exit(1)

	if options.verbose:
		print "k =",k
		print "B =", pprint(B)
		print "n =", pprint(n)
		
	f1 = stage1(k, B, options, cheatingPlaintext)
	print "Finished Stage 1 with a f1 of", f1
	f2 = stage2(k, B, f1, options, cheatingPlaintext)
	print "Finished Stage 2 with a f2 of", f2
	foundPlaintext = stage3(k, B, f2, options, cheatingPlaintext)
	print "Finished Stage 3..."
	print "Now performing OAEP Unpadding on plaintext..."

	if options.verbose:
		print pprint(foundPlaintext)
		
	recoveredPlaintext = unpad(k, foundPlaintext)
	print "The plaintext, in hexadecimal:"
	sys.stdout.write("0x")
	for b in recoveredPlaintext: sys.stdout.write(hex(ord(b))[2:].rjust(2, '0'))
	print
	
################################################################################
################################################################################
if __name__ == "__main__":
	n = 157864837766412470414898605682479126709913814457720048403886101369805832566211909035448137352055018381169566146003377316475222611235116218157405481257064897859932106980034542393008803178451117972197473517842606346821132572405276305083616404614783032204836434549683833460267309649602683257403191134393810723409
	e = 0x10001
	c = int('5033692c41c8a1bdc2c78eadffc47da73470b2d25c9dc0ce2c0d0282f0d5f845163ab6f2f296540c1a1090d826648e12644945ab922a125bb9c67f8caaef6b4abe06b92d3365075fbb5d8f19574ddb5ee80c0166303702bbba249851836a58c3baf23f895f9a16e5b15f2a698be1e3efb74d5c5c4fddc188835a16cf7c9c132c', 16)
	p = int('2ea4875381beb0f84818ce1c4df72574f194f7abefe9601b21da092f484fa886ff0de66edf8babd4bd5b35dfdb0e642382947270a8f197e3cbaaa37cb8f7007f4604794a51c3bd65f8d17bfad9e699726ff9f61b99762d130777872eb4e9f1532cf3bfbfc3d2ad5d8d4582cc90a2e59915c462967b19965f77225447ce660d', 16)

	parser = OptionParser()
	parser.add_option("-v", "--verbose", dest="verbose", action="store_true")
	parser.add_option("-c", "--cheat", dest="cheat", action="store_true")
	(options, args) = parser.parse_args()

	mangersOracle(n, e, c, options, cheatingPlaintext=p)

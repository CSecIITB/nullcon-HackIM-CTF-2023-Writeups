#!/usr/bin/env python3
from Crypto.Util.number import inverse
from utils import *

class EllipticCurve(object):
	def __init__(self, p, a, b, order = None):
		self.p = p
		self.a = a
		self.b = b
		self.n = order

	def __str__(self):
		return 'y^2 = x^3 + %dx + %d modulo %d' % (self.a, self.b, self.p)

	def __eq__(self, other):
		return (self.a, self.b, self.p) == (other.a, other.b, other.p)

class ECPoint(object):
	def __init__(self, curve, x, y, inf = False):
		self.x = x % curve.p
		self.y = y % curve.p
		self.curve = curve
		self.inf = inf
		if x == 0 and y == 0: self.inf = True

	def copy(self):
		return ECPoint(self.curve, self.x, self.y)
	
	def __neg__(self):
		return ECPoint(self.curve, self.x, -self.y, self.inf)

	def __add__(self, point):
		p = self.curve.p
		if self.inf:
			return point.copy()
		if point.inf:
			return self.copy()
		if self.x == point.x and (self.y + point.y) % p == 0:
			return ECPoint(self.curve, 0, 0, True)
		if self.x == point.x:
			lamb = (3*self.x**2 + self.curve.a) * inverse(2 * self.y, p) % p
		else:
			lamb = (point.y - self.y) * inverse(point.x - self.x, p) % p
		x = (lamb**2 - self.x - point.x) % p
		y = (lamb * (self.x - x) - self.y) % p
		return ECPoint(self.curve,x,y)

	def __sub__(self, point):
		return self + (-point)

	def __str__(self):
		if self.inf: return 'Point(inf)'
		return 'Point(%d, %d)' % (self.x, self.y)

	def __mul__(self, k):
		k = int(k)
		base = self.copy()
		res = ECPoint(self.curve, 0,0,True)
		while k > 0:
			if k & 1:
				res = res + base
			base = base + base
			k >>= 1
		return res

	def __eq__(self, point):
		return (self.inf and point.inf) or (self.x == point.x and self.y == point.y)

if __name__ == '__main__':
	p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
	a = -3
	b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
	n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
	curve = EllipticCurve(p,a,b, order = n)
	G = ECPoint(curve, 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

	C = ECPoint(curve,70229089239062543366905229206423088055130869903392321347510003012729950210213, 86674838449650650832521934345678948172759267691093089922358971250753728085610)
	print(C + G)

	x = 5353097454205048227453406131225155599776149179148399285518033353542120424329419279401740707753049021427943369625587221914361268942061721995705361252954928
	y = modular_sqrt(x**3 + a*x + b, p)
	T = ECPoint(curve, x, y) - G
	print(T)

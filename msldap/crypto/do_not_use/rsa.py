import random
import math

#https://qiita.com/su_/items/be1a98a2762f898d4159

class RSA():
	plaintext = ""
	ciphertext = []
	_e = _d = _n = 0
	_p = _q = 0
	_l = 0

	def __init__(self):
		pass
	def __del__(self):
		pass

	def set_plaintext(self,str):
		self.plaintext = str

	def _random(self):
		digit = 100
		return random.randrange(10**(digit - 1),10**digit)

	def get_public_key(self):
		return (self._e, self._n)

	def get_private_key(self):
		return (self._d, self._n)

	def get_key_data(self):
		return (self._l, self._p, self._q)

	def _lcm(self,p,q):
		return (p * q) // math.gcd(p, q)


	def _etension_euclid(self,x,y):
		c0, c1 = x, y
		a0, a1 = 1, 0
		b0, b1 = 0, 1

		while c1 != 0:
			 m = c0 % c1
			 q = c0 // c1

			 c0, c1 = c1, m
			 a0, a1 = a1, (a0 - q * a1)
			 b0, b1 = b1, (b0 - q * b1)

		return c0, a0, b0

	def _is_prime_number(self,q):
		cnt = 50

		q = abs(q)
		if q == 2: return True
		if q < 2 or q & 1 == 0: return False

		d = (q - 1) >> 1
		while d & 1 == 0:
			d >>= 1

		for i in range(cnt):
			a = random.randint(1,q - 1)
			t = d
			y = pow(a, t, q)
			while t != q - 1 and y != 1 and y != q - 1: 
				y = pow(y, 2, q)
				t <<= 1
			if y != q - 1 and t & 1 == 0:
				return False
		return True

	def GenerateKey(self,p = 0,q = 0,e = 0,d = 0,n = 0,l = 0):
		if p == 0:
			while True:
				p = self._random()
				if self._is_prime_number(p):break
		self._p = p

		if q == 0:
			while True:
				q = self._random()
				if self._is_prime_number(q) and p != q:break
		self._q = q

		if n == 0:
			n = p * q
		self._n = n

		if l == 0:
			l = self._lcm(p - 1, q  - 1)
		self._l = l

		if e == 0:
			while True:
				i = random.randint(2,l)
				if math.gcd(i, l) == 1:
				  e = i
				  break
		self._e = e

		if d == 0:
			_c, a, _b = self._etension_euclid(e, l)
			d = a % l
		self._d = d
		
	def encrypt_int(self, i):
		return pow(i, self._e,self._n)

	def encryption(self):
		en_str = ""

		for i in map((lambda x: pow(ord(x), self._e,self._n)),list(self.plaintext)):
			self.ciphertext.append(i)
			en_str += str(i)

		return en_str

	def decryption(self):
		cip = []
		de_str = ""
		for i in  list(self.ciphertext):
			tmp = chr(pow(i, self._d,self._n))
			cip.append(tmp)
			de_str += str(tmp)

		return de_str

if __name__ == '__main__':
	rsa = RSA()
	input = input(">>")
	rsa.set_plaintext(input)
	rsa.GenerateKey(0,0,65537)

	l, p, q = rsa.get_key_data()
	e, n = rsa.get_public_key()
	d, _n= rsa.get_private_key()

	print("p = " + str(p))
	print("q = " + str(q))
	print("n = " + str(n))
	print("l = " + str(l))
	print("e = " + str(e))
	print("d = " + str(d))


	en = rsa.encryption()
	de = rsa.decryption()
	print()

	print("C = " + str(en))
	print("P = " + str(de))
import random #for p and q values

#check if a number is prime, used for prime number generation 
def is_prime(n):
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

#generate a large prime number
def generate_prime():
    prime = random.randint(1000, 1000000)
    while not is_prime(prime):
        prime = random.randint(1000, 1000000)
    return prime

#calculate the greatest common divisor of a and b
def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

#calculate the modular inverse of a modulo m
def mod_inv(a, m):
    def egcd(a, b):
        if b == 0:
            return (1, 0, a)
        else:
            x, y, g = egcd(b, a % b)
            return (y, x - (a // b) * y, g)
    x, y, g = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    else:
        return x % m

#generate a public/private key pair for RSA encryption.
def generate_keypair(p, q):
    n = p * q
    phi = (p-1) * (q-1)
    #choose a public exponent e that is coprime to phi.
    #e should be a large number, but for simplicity I used a small fixed value.
    e = 13
    if gcd(e, phi) != 1:
        raise ValueError("e is not coprime to phi")
    #calculate the private exponent d as the modular inverse of e modulo phi.
    d = mod_inv(e, phi)
    return ((n, e), (n, d))

#encrypt a message using RSA encryption with the given public key.
def encrypt(msg, public_key):
    n, e = public_key
    m = int.from_bytes(msg.encode(), 'big')
    if m >= n:
        raise ValueError("message too large to encrypt")
    c = pow(m, e, n)
    return c

#decrypt a ciphertext using RSA encryption with the given private key.
def decrypt(ciphertext, private_key):
    n, d = private_key
    m = pow(ciphertext, d, n)
    msg = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
    return msg

#generate random prime numbers p and q.
p = generate_prime()
q = generate_prime()

#generate the public/private key pair.
public_key, private_key = generate_keypair(p, q)
print(f"p = {p}\nq = {q}\ne = {public_key[1]}\nd = {private_key[1]}")

#get the message to encrypt.
msg = input("Enter message: ")

#encrypt the message using the public key.
ciphertext = encrypt(msg, public_key)
print(f"Encrypted message = {ciphertext}")

#decrypt the ciphertext using the private key.
plaintext = decrypt(ciphertext, private_key)
print(f"Decrypted message = {plaintext}")

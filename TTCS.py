import tkinter as tk
from tkinter import filedialog, messagebox
import math
import random
from sympy import mod_inverse, isprime
import hashlib
import time
class EncryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ứng dụng mã hóa")

        self.label = tk.Label(root, text = "Nhập dữ liệu hoặc chọn file: ")
        self.label.pack(pady = 10)

        self.entry = tk.Entry(root, width = 50)
        self.entry.pack(pady = 10)

        self.file_button = tk.Button(root, text = "Chọn file", command = self.choose_file)
        self.file_button.pack(pady = 10)

        self.algorithm_label = tk.Label(root, text = "Chọn thuật toán mã hóa:")
        self.algorithm_label.pack(pady = 10)

        self.algorithm_var = tk.StringVar(value = "Default")
        self.rsa_radio = tk.Radiobutton(root, text = "RSA", variable = self.algorithm_var, value = "RSA")
        self.sha_radio = tk.Radiobutton(root, text = "SHA-256", variable = self.algorithm_var, value = "SHA")
        self.rsa_radio.pack()
        self.sha_radio.pack()
        
        self.submit_button = tk.Button(root, text = "Mã hóa", command = self.submit_data)
        self.submit_button.pack(pady = 10)

        self.output_text = tk.Text(root, height = 10, width = 100)
        self.output_text.pack(pady = 10)

        self.file_path = None

    def choose_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if self.file_path:
            self.entry.delete(0, tk.END)
            with open(self.file_path, 'r') as file:
                self.entry.insert(tk.END, file.read())

    def submit_data(self):
        data = self.entry.get()
        algorithm = self.algorithm_var.get()

        if algorithm == "SHA":
            sha256_obj = SHA256Hash(data)
            hashed_message = sha256_obj.encrypt()
            hashed_message_uselibrary = SHA256Hash.encrypt_usehashlib(data)
            time1, time2 = SHA256Hash.time_running(data)
            str1 = f"Kết quả mã hóa: \n"
            str2 = f"Không sử dụng thư viện: {hashed_message}\nThời gian thực hiện: {time1} giây\n"
            str3 = f"Sử dụng thư viện: {hashed_message_uselibrary}\nThời gian thực hiện: {time2} giây"
            result = str1 + str2 + str3
        else:
            public_key, private_key, prime_number = RSAEncryption.generate_keypair(8)
            encrypted_message = RSAEncryption.encrypt(public_key, data)
            str1 = f"Sinh cặp khóa ngẫu nhiên:\nKhóa công khai: {public_key}\nKhóa riêng tư: {private_key}\nCặp số nguyên tố lớn: {prime_number}\n"
            str2 = f"Kết quả mã hóa: {encrypted_message}\n"
            decrypted_message = RSAEncryption.decrypt(private_key, encrypted_message)
            str3 = f"Kết quả giải mã: {decrypted_message}"
            result = str1 + str2 + str3

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, result)

class BinaryConverter:
    @staticmethod
    def string_to_binary(string):
        return ''.join(format(byte, '08b') for byte in string.encode('utf-8'))
    
    @staticmethod
    def int_to_binary(n):
        return bin(n)[2:].zfill(32)

    @staticmethod
    def float_to_binary(n, precision = 32):
        frac_part = n - int(n)
        result = ''
        while precision:
            frac_part *= 2
            bit = int(frac_part)
            if bit == 1:
                frac_part -= bit
                result += '1'
            else:
                result += '0'
            precision -= 1
        return result

    @staticmethod
    def right_rotate(string, x):
        return string[-x:] + string[:-x]

    @staticmethod
    def right_shift(string, x):
        return '0' * x + string[:-x]

    @staticmethod
    def xor_string(*strings):
        max_len = max(len(s) for s in strings)
        strings = [s.zfill(max_len) for s in strings]
    
        result = list(strings[0])
        for i in range(1, len(strings)):
            current_str = strings[i]
            for j in range(len(result)):
                result[j] = '1' if result[j] != current_str[j] else '0'
        return ''.join(result)

    @staticmethod
    def and_string(*strings):
        max_len = max(len(s) for s in strings)
        strings = [s.zfill(max_len) for s in strings]
    
        result = list(strings[0])
        for i in range(1, len(strings)):
            current_str = strings[i]
            for j in range(len(result)):
                result[j] = '1' if result[j] == '1' and current_str[j] == '1' else '0'
        return ''.join(result)

    @staticmethod
    def not_string(string):
        return ''.join('1' if ch == '0' else '0' for ch in string)

    @staticmethod
    def add_binary_string(*strings):
        total = sum(int(s, 2) for s in strings)
        result = total % (2**32)
        return BinaryConverter.int_to_binary(result)

class HexConverter:
    @staticmethod
    def binary_to_hex(binary_string):
        index = int(binary_string, 2)
        result = hex(index)[2:]
        return result.zfill(8)

class SHA256Hash:
    def __init__(self, string):
        self.const = [
            '6a09e667', 'bb67ae85', '3c6ef372', 'a54ff53a', 
            '510e527f', '9b05688c', '1f83d9ab', '5be0cd19'
        ]
        self.k_values = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
        self.data = string
        
    def encrypt(self):
        result = BinaryConverter.string_to_binary(self.data) + '10000000'
        length = len(result)
        result = result.ljust((length + 64 + 511) // 512 * 512 - 64, '0')
        result += bin(len(self.data.encode('utf-8')) * 8)[2:].zfill(64)
        
        w = [result[32 * i: 32 * (i + 1)] for i in range(16)] + ['0' * 32] * 48
        for i in range(16, 64):
            s0 = BinaryConverter.xor_string(BinaryConverter.right_rotate(w[i - 15], 7), BinaryConverter.right_rotate(w[i - 15], 18), BinaryConverter.right_shift(w[i - 15], 3))
            s1 = BinaryConverter.xor_string(BinaryConverter.right_rotate(w[i - 2], 17), BinaryConverter.right_rotate(w[i - 2], 19), BinaryConverter.right_shift(w[i - 2], 10))
            w[i] = BinaryConverter.add_binary_string(w[i - 16], s0, w[i - 7], s1)

        self.const = [bin(int(x, 16))[2:].zfill(32) for x in self.const]
        
        self.k_values = [bin(x)[2:].zfill(32) for x in self.k_values]
        
        a, b, c, d, e, f, g, h = self.const
        
        for i in range(64):
            s1 = BinaryConverter.xor_string(BinaryConverter.right_rotate(e, 6), BinaryConverter.right_rotate(e, 11), BinaryConverter.right_rotate(e, 25))
            choice = BinaryConverter.xor_string(BinaryConverter.and_string(e, f), BinaryConverter.and_string(BinaryConverter.not_string(e), g))
            temp1 = BinaryConverter.add_binary_string(h, s1, choice, self.k_values[i], w[i])
            s0 = BinaryConverter.xor_string(BinaryConverter.right_rotate(a, 2), BinaryConverter.right_rotate(a, 13), BinaryConverter.right_rotate(a, 22))
            majority = BinaryConverter.xor_string(BinaryConverter.and_string(a, b), BinaryConverter.and_string(a, c), BinaryConverter.and_string(b, c))
            temp2 = BinaryConverter.add_binary_string(s0, majority)
            h = g
            g = f
            f = e
            e = BinaryConverter.add_binary_string(d, temp1)
            d = c
            c = b
            b = a
            a = BinaryConverter.add_binary_string(temp1, temp2)
        
        self.const[0] = BinaryConverter.add_binary_string(self.const[0], a)
        self.const[1] = BinaryConverter.add_binary_string(self.const[1], b)
        self.const[2] = BinaryConverter.add_binary_string(self.const[2], c)
        self.const[3] = BinaryConverter.add_binary_string(self.const[3], d)
        self.const[4] = BinaryConverter.add_binary_string(self.const[4], e)
        self.const[5] = BinaryConverter.add_binary_string(self.const[5], f)
        self.const[6] = BinaryConverter.add_binary_string(self.const[6], g)
        self.const[7] = BinaryConverter.add_binary_string(self.const[7], h)
        
        encrypt_message = ''.join(HexConverter.binary_to_hex(x) for x in self.const)
        return encrypt_message

    @staticmethod
    def encrypt_usehashlib(string):
        sha256_hash = hashlib.sha256()
        sha256_hash.update(string.encode())
        return sha256_hash.hexdigest()

    @staticmethod
    def time_running(string):
        start_time = time.time()
        sha256_obj = SHA256Hash(string)
        hashed_message = sha256_obj.encrypt()
        end_time = time.time()
        time1 = end_time - start_time
        start_time = time.time()
        hashed_message = SHA256Hash.encrypt_usehashlib(string)
        end_time = time.time()
        time2 = end_time - start_time
        return (time1, time2)

class RSAEncryption:
    @staticmethod
    def euclid_algorithm(a, b):
        while b != 0:
            a, b = b, a % b
        return a
    
    @staticmethod
    def generate_prime_candidate(length = 1024):
        p = random.getrandbits(length)
        p |= (1 << length - 1) | 1
        return p

    @staticmethod
    def generate_prime_number(length = 1024):
        p = 4
        while not isprime(p):
            p = RSAEncryption.generate_prime_candidate(length)
        return p

    @staticmethod
    def generate_keypair(length = 1024):
        p = RSAEncryption.generate_prime_number(length)
        q = RSAEncryption.generate_prime_number(length)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = random.randrange(1, phi)
        g = RSAEncryption.euclid_algorithm(e, phi)
        while g != 1:
            e = random.randrange(1, phi)
            g = RSAEncryption.euclid_algorithm(e, phi)
        d = mod_inverse(e, phi)
        return (e, n), (d, n), (p, q)

    @staticmethod
    def encrypt(pk, plaintext):
        key, n = pk
        cipher = [pow(ord(char), key, n) for char in plaintext]
        return cipher

    @staticmethod
    def decrypt(pk, ciphertext):
        key, n = pk
        plain = [chr(pow(char, key, n)) for char in ciphertext]
        return ''.join(plain)
    
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptApp(root)
    root.mainloop()
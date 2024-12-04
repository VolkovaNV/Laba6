import tkinter as tk
import struct

# тело гост шифр
def pad(data: bytes) -> bytes:
    padding_len = 8 - (len(data) % 8)
    return data + bytes([padding_len] * padding_len)

def nePad(data: bytes) -> bytes:
    padding_len = data[-1]
    return data[:-padding_len]

def rol(value: int, shift: int) -> int:
    rol = ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))
    return rol

sBlocks = [
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11], [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3], [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2], [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14], [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 14, 3, 11, 6, 8, 12]
]

def substitute(value: int) -> int:
    result = 0
    for i in range(8):
        s_block = sBlocks[i][(value >> (4 * i)) & 0xF]
        result |= s_block << (4 * i)
    return result

def gostround(left: int, right: int, key: int) -> (int, int):
    temp = (left + key) % (2 ** 32)
    temp = substitute(temp)
    temp = rol(temp, 11)
    new_right = right ^ temp
    return new_right, left

def gostZah_block(block: bytes, key: bytes) -> bytes:
    left = int.from_bytes(block[:4], byteorder='little')
    right = int.from_bytes(block[4:], byteorder='little')
    key_parts = [int.from_bytes(key[i:i+4], byteorder='little') for i in range(0, 32, 4)]
    for i in range(24):
        right, left = gostround(left, right, key_parts[i % 8])
    for i in range(8):
        right, left = gostround(left, right, key_parts[7 - i])
    return left.to_bytes(4, byteorder='little') + right.to_bytes(4, byteorder='little')

def generate_keystream(key: bytes, length: int) -> bytes:
    keystream = b''
    counter = 0
    while len(keystream) < length:
        counter_bytes = counter.to_bytes(8, byteorder='little')
        keystream += gostZah_block(counter_bytes, key)
        counter += 1
    return keystream[:length]

# Мейера-Матиса хэш-функция так называется 1 формула. Не знала как её правильно в коментах написать
def meyer_mathias_hash(data: bytes, key: bytes) -> bytes:
    hash_value = b'\x00' * 32  # начальное значение
    padded_data = pad(data)
    for i in range(0, len(padded_data), 32):
        block = padded_data[i:i+32]
        hash_value = gostZah_block(hash_value, key)
        hash_value = bytes(a ^ b for a, b in zip(hash_value, block))
    return hash_value[:32]

# конец тельца гост шифра 

def Zah():
    text = text_entry.get().strip().encode()
    key = key_entry.get().encode()
    keystream = generate_keystream(key, len(text))
    Zahed = bytes(a ^ b for a, b in zip(text, keystream))
    Res.delete("1.0", tk.END)
    Res.insert(tk.END, Zahed.hex())

def Rah():
    zahMsg = bytes.fromhex(text_entry.get().strip())
    key = key_entry.get().encode()
    keystream = generate_keystream(key, len(zahMsg))
    Rahed = bytes(a ^ b for a, b in zip(zahMsg, keystream))
    Res.delete("1.0", tk.END)
    Res.insert(tk.END, Rahed.decode())

def Hash():
    text = text_entry.get().strip().encode()
    key = key_entry.get().encode()
    hashed_value = meyer_mathias_hash(text, key)
    Res.delete("1.0", tk.END)
    Res.insert(tk.END, hashed_value.hex())

root = tk.Tk()
root.title("Лабораторная №6")

text_label = tk.Label(root, text="Введите сообщение:")
text_label.grid(row=0, column=0)
key_label = tk.Label(root, text="Ключ:")
key_label.grid(row=1, column=0)
result_label = tk.Label(root, text="Результат:")
result_label.grid(row=3, column=0)
text_entry = tk.Entry(root)
text_entry.grid(row=0, column=1)
key_entry = tk.Entry(root)
key_entry.grid(row=1, column=1)
Res = tk.Text(root, height=5, width=50)
Res.grid(row=3, column=1)

Zah_button = tk.Button(root, text="Зашифровать", command=Zah)
Zah_button.grid(row=2, column=0)
Rah_button = tk.Button(root, text="Расшифровать", command=Rah)
Rah_button.grid(row=2, column=1)
Hash_button = tk.Button(root, text="Хэшировать", command=Hash)
Hash_button.grid(row=2, column=2)

root.mainloop()

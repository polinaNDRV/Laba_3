import secrets
import tkinter as tk
from tkinter import messagebox

S = [
    [0x0, 0x4, 0xE, 0xB, 0x6, 0x1, 0x5, 0xC, 0xD, 0xA, 0x9, 0x8, 0x3, 0x2, 0x7, 0xF],
    [0x7, 0xC, 0xB, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0, 0xF, 0xE, 0xD, 0xA, 0x9, 0x8],
    [0x3, 0x0, 0x7, 0x2, 0x6, 0x5, 0x1, 0x4, 0xF, 0xC, 0xB, 0xA, 0x9, 0x8, 0xD, 0xE],
    [0x6, 0x4, 0x0, 0x7, 0x5, 0x1, 0x2, 0x3, 0xF, 0xE, 0x9, 0xA, 0xD, 0xC, 0x8, 0xB],
    [0x1, 0x5, 0x0, 0x6, 0x3, 0x2, 0x7, 0x4, 0xB, 0xC, 0xD, 0xE, 0xF, 0xA, 0x9, 0x8],
    [0x1, 0x7, 0x5, 0x0, 0x3, 0x4, 0x6, 0x2, 0xA, 0xB, 0xD, 0xE, 0xF, 0x9, 0x8, 0xC],
    [0x4, 0x5, 0x0, 0x3, 0x2, 0x1, 0x6, 0x7, 0xF, 0xE, 0xC, 0x9, 0xA, 0xB, 0xD, 0x8],
    [0x3, 0x5, 0x0, 0x7, 0x1, 0x4, 0x2, 0x6, 0xB, 0xC, 0xD, 0xE, 0xF, 0xA, 0x8, 0x9],
]

P = [i for i in range(32)]


def generate_key():
    return int.from_bytes(secrets.token_bytes(32), byteorder='big')


def s(n):
    result = 0
    for i in range(8):
        byte = (n >> (i * 4)) & 0xf
        index = i % len(S)
        result |= S[index][byte] << (i * 4)
    return result


def p(n):
    return sum(((n >> i) & 1) << P[i] for i in range(32))


def round_function(block: int, round_key: int):
    left = (block >> 32) & ((1 << 32) - 1)
    right = block & ((1 << 32) - 1)

    right_xor_key = right ^ round_key
    sub = s(right_xor_key)
    per = p(sub)

    new_left = right
    new_right = left ^ per

    return (new_left << 32) | new_right


def encrypt(data: int, key: int):
    round_keys = [key >> (i * 8) & ((1 << 32) - 1) for i in range(8)]
    block = data

    for i in range(32):
        round_key = round_keys[i % len(round_keys)]
        block = round_function(block, round_key)

    return block




class GOSTApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Шифр ГОСТ")

        self.generate_key_button = tk.Button(root, text="Сгенерировать ключ", command=self.generate_key)
        self.generate_key_button.pack()

        self.input_label = tk.Label(root, text="Введите текст для шифрования:")
        self.input_label.pack()

        self.input_entry = tk.Entry(root, width=50)
        self.input_entry.pack()

        self.encrypt_button = tk.Button(root, text="Зашифровать", command=self.encrypt_data)
        self.encrypt_button.pack()

        self.key_label = tk.Label(root, text="")
        self.key_label.pack()

        self.ciphertext_label = tk.Label(root, text="")
        self.ciphertext_label.pack()

        self.decrypted_label = tk.Label(root, text="")
        self.decrypted_label.pack()

        # Изначально ключ пустой
        self.key = None

    def generate_key(self):
        self.key = generate_key()
        self.key_label.config(text=f"Сгенерированный ключ: 0x{self.key:064x}")

    def encrypt_data(self):
        if self.key is None:
            messagebox.showerror("Ошибка", "Сначала сгенерируйте ключ.")
            return

        input_text = self.input_entry.get()
        if not input_text:
            messagebox.showerror("Ошибка", "Введите текст для шифрования.")
            return

        byte_data = input_text.encode('utf-8')
        data = int.from_bytes(byte_data[:8], byteorder='big')

        ciphertext = encrypt(data, self.key)

        encrypted_bytes = ciphertext.to_bytes(8, byteorder='big')

        self.ciphertext_label.config(text=f"Зашифрованный текст: 0x{ciphertext:016x}")


if __name__ == "__main__":
    root = tk.Tk()
    app = GOSTApp(root)
    root.mainloop()
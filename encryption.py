import numpy as np

def hill_cipher_encrypt(PT, key):
    # Menghapus spasi dan mengubah huruf kecil
    PT = PT.lower()

    # Mendefinisikan abjad dengan nomor, termasuk karakter khusus
    EAM = {chr(i): i - 97 for i in range(32, 127)}

    # Mendapatkan nomor dari plaintext
    PT_numbers = [EAM.get(char, None) for char in PT]

    # Validasi kunci dan plaintext
    if any(num is None for num in PT_numbers):
        print("Error: Karakter tidak valid dalam plaintext.")
        return None

    key_numbers = [EAM.get(char, None) for char in key]

    # Validasi kunci
    if any(num is None for num in key_numbers):
        print("Error: Karakter tidak valid dalam kunci.")
        return None

    BL = len(key) // 2  # Panjang Blok

    # Memeriksa apakah matriks kunci dapat diinvers
    try:
        key_matrix = np.array(key_numbers).reshape(BL, BL)
        np.linalg.inv(key_matrix)
    except np.linalg.LinAlgError:
        print("Error: Matriks kunci tidak dapat diinvers.")
        return None

    # Mengubah nomor PT menjadi matriks
    PT_array = np.array(PT_numbers)

    # Mengisi spasi pada plaintext jika panjangnya tidak habis dibagi oleh BL
    if len(PT_array) % BL != 0:
        padding = BL - (len(PT_array) % BL)
        PT_array = np.concatenate([PT_array, np.zeros(padding, dtype=int)])

    PT_blocks = np.split(PT_array, len(PT_array) // BL)

    CT_blocks = [np.matmul(PT_blocks[i], key_matrix) % 94 for i in range(len(PT_blocks))]

    CT_array = np.concatenate(CT_blocks)

    # Mengonversi kembali ke karakter, memperhatikan rentang ASCII
    CT = ''.join([chr(i + 32) for i in CT_array])

    return CT

# Contoh penggunaan
PT = input('Masukkan plaintext: ')
key = "test"

CT = hill_cipher_encrypt(PT, key)
if CT:
    print("Ciphertext:", CT)
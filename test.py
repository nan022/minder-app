import numpy as np

# Fungsi untuk menghitung invers matriks modulo
def matrix_mod_inverse(matrix, modulus):
    det = int(np.round(np.linalg.det(matrix)))  # Menghitung determinan matriks
    det_inverse = pow(det, -1, modulus)  # Menghitung invers determinan
    adjugate = (det * np.linalg.inv(matrix)).round()  # Menghitung matriks adjugate
    inverse = (adjugate * det_inverse) % modulus  # Menghitung invers matriks
    return inverse

# Fungsi untuk mengenkripsi teks menggunakan Hill Cipher
def hill_cipher_encrypt(plain_text, key_matrix):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    plain_text = plain_text.upper()  # Mengubah teks menjadi huruf kapital
    encrypted_text = ""  # Inisialisasi teks terenkripsi sebagai string kosong
    
    n = len(key_matrix)  # Ukuran matriks kunci
    
    # Pad teks jika panjangnya tidak kelipatan dari n
    if len(plain_text) % n != 0:
        plain_text += "X" * (n - (len(plain_text) % n))
    
    # Loop melalui teks plain dan enkripsi per blok n
    for i in range(0, len(plain_text), n):
        chunk = plain_text[i:i + n]  # Ambil potongan teks sepanjang n
        chunk_vector = []
        
        # Buat vektor karakter, mengabaikan spasi
        for char in chunk:
            if char in alphabet:
                chunk_vector.append(alphabet.index(char))
            else:
                chunk_vector.append(ord(char) - ord('A'))
        
        encrypted_chunk = np.dot(key_matrix, chunk_vector) % 26  # Enkripsi menggunakan matriks kunci
        encrypted_text += "".join([alphabet[int(idx)] if isinstance(idx, (int, np.integer)) else chr(idx + ord('A')) for idx in encrypted_chunk])  # Gabungkan hasil enkripsi
    
    return encrypted_text  # Mengembalikan teks terenkripsi

# Fungsi untuk mendekripsi teks yang telah dienkripsi menggunakan Hill Cipher
def hill_cipher_decrypt(encrypted_text, key_matrix):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    encrypted_text = encrypted_text.upper()  # Mengubah teks terenkripsi menjadi huruf kapital
    decrypted_text = ""  # Inisialisasi teks terdekripsi sebagai string kosong
    
    n = len(key_matrix)  # Ukuran matriks kunci
    
    # Menghitung invers matriks kunci
    key_inverse = matrix_mod_inverse(key_matrix, 26)
    
    # Loop melalui teks terenkripsi dan mendekripsi per blok n
    for i in range(0, len(encrypted_text), n):
        chunk = encrypted_text[i:i + n]  # Ambil potongan teks terenkripsi sepanjang n
        chunk_vector = np.array([alphabet.index(char) for char in chunk])  # Buat vektor karakter
        decrypted_chunk = np.dot(key_inverse, chunk_vector) % 26  # Mendekripsi menggunakan invers matriks kunci
        decrypted_text += "".join([alphabet[int(idx)] for idx in decrypted_chunk])  # Gabungkan hasil dekripsi
    
    return decrypted_text  # Mengembalikan teks terdekripsi

# Contoh penggunaan dengan matriks kunci 2x2
key_matrix = np.array([[2, 1], [3, 4]])  # Matriks kunci 2x2
plain_text = input('Masukan Plaintext: ')  # Teks biasa yang akan dienkripsi
encrypted_text = hill_cipher_encrypt(plain_text, key_matrix)  # Enkripsi teks
decrypted_text = hill_cipher_decrypt(encrypted_text, key_matrix)  # Dekripsi teks

# Mencetak teks biasa, teks terenkripsi, dan teks terdekripsi
print("Plain Text:", plain_text)
print("Encrypted Text:", encrypted_text)
print("Decrypted Text:", decrypted_text)
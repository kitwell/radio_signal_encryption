
# Были установлены:
# pip install gostcrypto  <- и отсюда
# pip install streebog_rs
# pip install streebog_lc <- отсюда взят код


import gostcrypto
from streebog_rs import streebog_256, streebog_512

# Функция для вычисления хэша 256 бит
def compute_streebog256(data: bytes) -> str:
    hash_obj = gostcrypto.gosthash.new('streebog256', data=data)
    return hash_obj.hexdigest()

# Функция для вычисления хэша 512 бит
def compute_streebog512(data: bytes) -> str:
    hash_obj = gostcrypto.gosthash.new('streebog512', data=data)
    return hash_obj.hexdigest()

def compute_hashes(data: bytes):
    """Вычисляет хэши Streebog для переданных данных"""
    hash256 = streebog_256(data)
    hash512 = streebog_512(data)
    return hash256, hash512

# Пример использования
if __name__ == "__main__":
    test_data = b"Hello, World!"
    print(f"256 (gostcrypto): {compute_streebog256(test_data)}")
    print(f"512 (gostcrypto): {compute_streebog512(test_data)}")

    h256, h512 = compute_hashes(test_data)
    print(f"\n256 (streebog_rs): {h256}")
    print(f"512 (streebog_rs): {h512}")

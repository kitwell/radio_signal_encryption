"""
Реализация ГОСТ 34.11-2012 (Стрибог) на чистом Python

"""

from typing import Union
from pathlib import Path

from consts import *

def _add512(a: bytes, b: bytes) -> bytes:
    """Сложение двух 64-байтовых блоков по модулю 2^512"""
    res = bytearray(64)
    tmp = 0
    for i in range(64):
        idx = 63 - i
        tmp = a[idx] + b[idx] + (tmp >> 8)
        res[idx] = tmp & 0xFF
    return bytes(res)


def _xor(a: bytes, b: bytes) -> bytes:
    """Побайтовое XOR двух 64-байтовых блоков"""
    return bytearray(x ^ y for x, y in zip(a, b))


def _transform_s(data: bytearray):
    """Неллинейное преобразование S (замена по таблице PI)"""
    for i in range(64):
        data[i] = PI[data[i]]


def _transform_p(data: bytearray):
    """Перестановка P (по таблице TAU)"""
    temp = bytes(data)
    for i, pos in enumerate(TAU):
        data[i] = temp[pos]


def _bytes_to_u64s(data: bytes) -> list:
    """Преобразование 64 байт в 8 uint64 (little-endian)"""
    result = []
    for i in range(0, 64, 8):
        value = 0
        for j in range(8):
            value |= data[i + j] << (8 * j)
        result.append(value)
    return result


def _u64s_to_bytes(values: list) -> bytes:
    """Преобразование 8 uint64 в 64 байта (little-endian)"""
    result = bytearray(64)
    for i, val in enumerate(values):
        for j in range(8):
            result[i * 8 + j] = (val >> (8 * j)) & 0xFF
    return bytes(result)


def _calc_buffer_precomp(input64: int) -> int:
    """Линейное преобразование L с предвычислением"""
    result = 0
    for i in range(8):
        shift = 8 * (7 - i)
        byte_val = (input64 >> shift) & 0xFF
        # Используем APrecomp (нужно добавить из Go-кода)
        result ^= APrecomp[byte_val][7 - i]
    return result


def _transform_l(data: bytearray):
    """Линейное преобразование L"""
    u64s = _bytes_to_u64s(data)
    buffers = [_calc_buffer_precomp(val) for val in u64s]
    new_data = _u64s_to_bytes(buffers)
    data[:] = new_data


# ============================================================================
# ОСНОВНЫЕ ФУНКЦИИ СТРИБОГА
# ============================================================================

class Streebog:
    """Реализация хэш-функции Стрибог (ГОСТ 34.11-2012)"""
    
    def __init__(self, digest_size: int = 512):
        """
        digest_size: 256 или 512 бит
        """
        self.digest_size = digest_size
        self._use256 = (digest_size == 256)
        
        # Инициализация состояния
        self._hash = bytearray(64)
        self._n = bytearray(64)
        self._sigma = bytearray(64)
        self._block_size = bytearray(64)
        self._buffer = bytearray()
        
        if self._use256:
            # Для 256-битного хэша начальное состояние - все единицы
            self._hash[:] = bytes([1]) * 64
    
    def _transform_g(self, message: bytes):
        """Функция сжатия G"""
        # Ключи = N xor Hash
        keys = _xor(self._n, self._hash)
        
        # Преобразование ключей
        _transform_s(keys)
        _transform_p(keys)
        _transform_l(keys)
        
        # Состояние = message xor keys
        state = _xor(message, keys)
        
        # 12 раундов шифрования
        for i in range(12):
            _transform_s(state)
            _transform_p(state)
            _transform_l(state)
            
            # Обновление ключей через KeySchedule
            keys = _xor(keys, Cn[i])
            _transform_s(keys)
            _transform_p(keys)
            _transform_l(keys)
            
            state = _xor(state, keys)
        
        # Обновление хэша: Hash = state xor Hash xor message
        self._hash = _xor(state, self._hash)
        self._hash = _xor(self._hash, message)   
    
    def update(self, data: bytes):
        """Обновление хэша новыми данными"""
        self._buffer += data
        
        while len(self._buffer) >= 64:
            chunk = self._buffer[:64]
            self._buffer = self._buffer[64:]
            
            # В Go-коде: for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 { b[i], b[j] = b[j], b[i] }
            # Это reverse, а не просто bytes(reversed())
            chunk = bytes(reversed(chunk))
            
            self._transform_g(chunk)
            
            # Обновление N: N = N + 512 (0x200 бит = 0x02 в block_size[62:63])
            block_size = bytearray(64)
            block_size[62] = 0x02  # 512 бит = 0x0200
            self._n = bytearray(_add512(self._n, block_size))
            
            # Обновление Sigma: Sigma = Sigma + chunk
            self._sigma = bytearray(_add512(self._sigma, chunk))
    
    def digest(self) -> bytes:
        """Получение финального хэша"""
        remaining = len(self._buffer)
        
        if remaining > 0:
            chunk = bytes(reversed(self._buffer))
            padded = bytearray(64)
            padded[:len(chunk)] = chunk
            padded[remaining] = 1
            
            block_size = bytearray(64)
            block_size[62] = (remaining * 8) >> 8
            block_size[63] = (remaining * 8) & 0xFF
            
            self._transform_g(padded)
            self._n = bytearray(_add512(self._n, block_size))
            self._sigma = bytearray(_add512(self._sigma, padded))
        
        # Финальные шаги: G(0, Hash, N) и G(0, Hash, Sigma)
        zero = bytearray(64)
        self._transform_g(zero)
        self._transform_g(self._sigma)
        
        # Разворачиваем результат обратно
        result = bytes(reversed(self._hash))
        
        if self._use256:
            return result[32:]
        return result
    
    def hexdigest(self) -> str:
        """Получение хэша в шестнадцатеричном формате"""
        return self.digest().hex()


# ============================================================================
# УДОБНЫЕ ФУНКЦИИ ДЛЯ ВЫЗОВА (аналогичные streebog-lc)
# ============================================================================

def hash256_bytes(data: bytes) -> str:
    """Вычисление хэша 256 бит от байтов"""
    hasher = Streebog(digest_size=256)
    hasher.update(data)
    return hasher.hexdigest()


def hash512_bytes(data: bytes) -> str:
    """Вычисление хэша 512 бит от байтов"""
    hasher = Streebog(digest_size=512)
    hasher.update(data)
    return hasher.hexdigest()


def hash256_file(path: Union[str, Path]) -> str:
    """Вычисление хэша 256 бит от файла"""
    path = Path(path)
    hasher = Streebog(digest_size=256)
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()


def hash512_file(path: Union[str, Path]) -> str:
    """Вычисление хэша 512 бит от файла"""
    path = Path(path)
    hasher = Streebog(digest_size=512)
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()


# ============================================================================
# ТЕСТИРОВАНИЕ
# ============================================================================

def main():
    # Тестовые векторы
    test_data = b"Hello, World!"
    
    print("Тестирование Streebog (чистый Python)")
    print("=" * 50)
    
    # 256 бит
    hash256 = hash256_bytes(test_data)
    print(f"Streebog-256('{test_data.decode()}'): {hash256}")
    
    # 512 бит
    hash512 = hash512_bytes(test_data)
    print(f"Streebog-512('{test_data.decode()}'): {hash512}")
    
    # Сравнение с известным значением (опционально)
    expected_256 = "eb4672c915b0e4f19ce949b9a8fff8ba6b36172ed168458d6a75e752e66faaf3"
    if hash256 == expected_256:
        print("\n✅ Тест пройден: хэш 256 бит совпадает с эталоном")
    else:
        print(f"\n⚠️ Хэш 256 бит отличается от эталона")
        print(f"Получено:  {hash256}")
        print(f"Ожидалось: {expected_256}")


if __name__ == "__main__":
    main()
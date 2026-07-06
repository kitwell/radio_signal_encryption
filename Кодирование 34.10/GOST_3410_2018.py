from os import urandom
from typing import Tuple, Optional
from GOST_CURVES import CURVES_256


class GOST3410_2018_256:
    """
    ГОСТ 34.10-2018 (256 бит) - реализация электронной подписи
    """
    
    def __init__(self, p: int, q: int, a: int, b: int, x: int, y: int):
        """
        Инициализация кривой ГОСТ 34.10-2018 (256 бит)
        
        :param p: характеристика простого поля
        :param q: порядок подгруппы эллиптической кривой
        :param a, b: коэффициенты уравнения кривой в канонической форме
        :param x, y: координаты точки генератора
        """
        self.p = p
        self.q = q
        self.a = a
        self.b = b
        self.Gx = x
        self.Gy = y
        
        # Проверка валидности точки генератора
        r1 = (y * y) % p
        r2 = ((x * x + a) * x + b) % p
        if r1 != r2:
            raise ValueError("Невалидные параметры кривой")
    
    def _mod_normalize(self, v: int) -> int:
        """Приведение числа к положительному значению в поле"""
        if v < 0:
            return v + self.p
        return v
    
    def _point_add(self, x1: int, y1: int, x2: int, y2: int) -> Tuple[int, int]:
        """Сложение двух точек на эллиптической кривой"""
        if x1 == x2 and y1 == y2:
            # Удвоение точки
            lambd = ((3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p)) % self.p
        else:
            # Сложение
            dx = self._mod_normalize(x2 - x1) % self.p
            dy = self._mod_normalize(y2 - y1) % self.p
            lambd = (dy * pow(dx, -1, self.p)) % self.p
        
        x3 = self._mod_normalize(lambd * lambd - x1 - x2) % self.p
        y3 = self._mod_normalize(lambd * (x1 - x3) - y1) % self.p
        
        return x3, y3
    
    def scalar_mult(self, scalar: int, x: Optional[int] = None, y: Optional[int] = None) -> Tuple[int, int]:
        """
        Скалярное умножение точки на число
        
        :param scalar: множитель (приватный ключ или случайное число k)
        :param x, y: координаты точки (по умолчанию - точка генератора)
        :return: (x, y) результирующей точки
        """
        if scalar == 0:
            raise ValueError("Скаляр не может быть равен 0")
        
        x = x or self.Gx
        y = y or self.Gy
        
        # Бинарный метод "double-and-add"
        result_x, result_y = x, y
        scalar -= 1
        
        while scalar:
            if scalar & 1:
                result_x, result_y = self._point_add(result_x, result_y, x, y)
            scalar >>= 1
            x, y = self._point_add(x, y, x, y)
        
        return result_x, result_y
    
    def public_key(self, private_key: int) -> Tuple[int, int]:
        """
        Генерация открытого ключа из приватного
        
        :param private_key: приватный ключ (1 < key < q)
        :return: (x, y) открытого ключа
        """
        if private_key <= 0 or private_key >= self.q:
            raise ValueError("Приватный ключ вне допустимого диапазона")
        
        return self.scalar_mult(private_key)
    
    def sign(self, private_key: int, digest: bytes, random_k: Optional[bytes] = None) -> bytes:
        """
        Создание электронной подписи
        
        :param private_key: приватный ключ (1 < key < q)
        :param digest: хеш сообщения (32 байта, уже вычисленный)
        :param random_k: опциональное случайное число k (32 байта)
        :return: подпись (64 байта: s || r)
        """
        q = self.q
        size = 32
        
        # Преобразуем хеш в число
        e = int.from_bytes(digest, 'big') % q
        if e == 0:
            e = 1
        
        while True:
            # Генерация случайного k
            if random_k is None:
                random_k = urandom(size)
            elif len(random_k) != size:
                raise ValueError(f"Длина random_k должна быть {size} байт")
            
            k = int.from_bytes(random_k, 'big') % q
            if k == 0:
                continue
            
            # Вычисление r = (k*G).x mod q
            r, _ = self.scalar_mult(k)
            r %= q
            if r == 0:
                continue

            s = (private_key * r + k * e) % q
            if s == 0:
                continue
            
            break
        
        # Подпись: s || r (по 32 байта)
        return s.to_bytes(size, 'big') + r.to_bytes(size, 'big')
    
    def verify(self, public_key: Tuple[int, int], digest: bytes, signature: bytes) -> bool:
        """
        Проверка электронной подписи
        
        :param public_key: (x, y) открытого ключа
        :param digest: хеш сообщения (32 байта, уже вычисленный)
        :param signature: подпись (64 байта: s || r)
        :return: True если подпись верна, иначе False
        """
        size = 32
        q = self.q
        p = self.p
        
        # Проверка длины подписи
        if len(signature) != 64:
            raise ValueError("Длина подписи должна быть 64 байта")
        
        # Распаковка подписи
        s = int.from_bytes(signature[:size], 'big')
        r = int.from_bytes(signature[size:], 'big')
        
        # Проверка диапазонов
        if r <= 0 or r >= q or s <= 0 or s >= q:
            return False
        
        # Преобразование хеша
        e = int.from_bytes(digest, 'big') % q
        if e == 0:
            e = 1
        
        # Вычисление v = e^(-1) mod q
        v = pow(e, -1, q)
        
        # Вычисление z1 = s * v mod q
        z1 = (s * v) % q
        
        # Вычисление z2 = -r * v mod q
        z2 = (q - (r * v) % q) % q
        
        # Вычисление точки R = z1*G + z2*Pub
        x1, y1 = self.scalar_mult(z1)
        x2, y2 = self.scalar_mult(z2, public_key[0], public_key[1])
        
        # Сложение двух точек
        if x1 == x2 and y1 == y2:
            # Удвоение
            lambd = ((3 * x1 * x1 + self.a) * pow(2 * y1, -1, p)) % p
        else:
            dx = self._mod_normalize(x2 - x1) % p
            dy = self._mod_normalize(y2 - y1) % p
            lambd = (dy * pow(dx, -1, p)) % p
        
        x3 = self._mod_normalize(lambd * lambd - x1 - x2) % p
        # y3 не нужен для проверки
        
        # Сравнение R.x с r
        return (x3 % q) == r


# Кривая по умолчанию (параметры A)
DEFAULT_CURVE_256 = "id-tc26-gost-3410-2018-256-paramSetA"


def create_curve(curve_name: str = DEFAULT_CURVE_256) -> GOST3410_2018_256:
    """
    Создание экземпляра кривой по имени
    
    :param curve_name: имя кривой из словаря CURVES_256
    :return: экземпляр GOST3410_2018_256
    """
    if curve_name not in CURVES_256:
        raise ValueError(f"Неизвестная кривая: {curve_name}")
    
    params = CURVES_256[curve_name]
    return GOST3410_2018_256(
        p=params["p"],
        q=params["q"],
        a=params["a"],
        b=params["b"],
        x=params["x"],
        y=params["y"]
    )


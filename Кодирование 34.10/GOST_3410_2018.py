from os import urandom
from typing import Tuple, Optional


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
            
            # Вычисление s = (private_key * r + k * e) mod q
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


# Стандартные кривые ГОСТ 34.10-2018 (256 бит)
CURVES_256 = {
    "id-tc26-gost-3410-2018-256-paramSetA": {
        "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97,
        "q": 0x400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67,
        "a": 0xC2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335,
        "b": 0x295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513,
        "x": 0x91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28,
        "y": 0x32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C,
    },
    "id-tc26-gost-3410-2018-256-paramSetB": {
        "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97,
        "q": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893,
        "a": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94,
        "b": 0x00000000000000000000000000000000000000000000000000000000000000A6,
        "x": 0x0000000000000000000000000000000000000000000000000000000000000001,
        "y": 0x8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14,
    },
    "id-tc26-gost-3410-2018-256-paramSetC": {
        "p": 0x8000000000000000000000000000000000000000000000000000000000000C99,
        "q": 0x800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F,
        "a": 0x8000000000000000000000000000000000000000000000000000000000000C96,
        "b": 0x3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B,
        "x": 0x0000000000000000000000000000000000000000000000000000000000000001,
        "y": 0x3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC,
    },
    "id-tc26-gost-3410-2018-256-paramSetD": {
        "p": 0x9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B,
        "q": 0x9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9,
        "a": 0x9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598,
        "b": 0x000000000000000000000000000000000000000000000000000000000000805A,
        "x": 0x0000000000000000000000000000000000000000000000000000000000000000,
        "y": 0x41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67,
    },
}

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


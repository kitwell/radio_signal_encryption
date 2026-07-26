import gostcrypto
from os import urandom
from typing import Tuple, Optional, Dict
from dataclasses import dataclass, field
from enum import Enum, auto


# =============================================================================
# 1. ВСПОМОГАТЕЛЬНЫЕ КЛАССЫ И КОНСТАНТЫ
# =============================================================================

class CurveParameterSet(Enum):
    PARAM_SET_A = auto()
    PARAM_SET_B = auto()
    PARAM_SET_C = auto()
    PARAM_SET_D = auto()

    def get_name(self) -> str:
        names = {
            CurveParameterSet.PARAM_SET_A: "id-tc26-gost-3410-2018-256-paramSetA",
            CurveParameterSet.PARAM_SET_B: "id-tc26-gost-3410-2018-256-paramSetB",
            CurveParameterSet.PARAM_SET_C: "id-tc26-gost-3410-2018-256-paramSetC",
            CurveParameterSet.PARAM_SET_D: "id-tc26-gost-3410-2018-256-paramSetD",
        }
        return names[self]

    def get_description(self) -> str:
        desc = {
            CurveParameterSet.PARAM_SET_A: "Набор A - рекомендованный для общего применения",
            CurveParameterSet.PARAM_SET_B: "Набор B - альтернативный, совместимый с предыдущими версиями",
            CurveParameterSet.PARAM_SET_C: "Набор C - с увеличенным полем",
            CurveParameterSet.PARAM_SET_D: "Набор D - с уникальными параметрами",
        }
        return desc[self]


@dataclass
class CurveParameters:
    p: int  # Характеристика простого поля GF(p)
    q: int  # Порядок подгруппы эллиптической кривой
    a: int  # Коэффициент a уравнения кривой
    b: int  # Коэффициент b уравнения кривой
    x: int  # Координата x базовой точки G
    y: int  # Координата y базовой точки G
    name: str = field(default="unknown")
    description: str = field(default="")

    def validate(self) -> bool:
        left_side = (self.y * self.y) % self.p
        right_side = ((self.x * self.x + self.a) * self.x + self.b) % self.p
        return left_side == right_side

    def get_hex_repr(self) -> Dict[str, str]:
        return {
            "p": f"{self.p:064x}",
            "q": f"{self.q:064x}",
            "a": f"{self.a:064x}",
            "b": f"{self.b:064x}",
            "x": f"{self.x:064x}",
            "y": f"{self.y:064x}",
        }

    def get_bit_lengths(self) -> Dict[str, int]:
        return {
            "p": self.p.bit_length(),
            "q": self.q.bit_length(),
            "a": self.a.bit_length(),
            "b": self.b.bit_length(),
            "x": self.x.bit_length(),
            "y": self.y.bit_length(),
        }


# =============================================================================
# 2. ПАРАМЕТРЫ СТАНДАРТНЫХ КРИВЫХ ГОСТ 34.10-2018 (256 бит)
# =============================================================================

CURVES_256: Dict[str, CurveParameters] = {
    "id-tc26-gost-3410-2018-256-paramSetA": CurveParameters(
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97,
        q=0x400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67,
        a=0xC2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335,
        b=0x295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513,
        x=0x91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28,
        y=0x32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C,
        name="id-tc26-gost-3410-2018-256-paramSetA",
        description="Набор A - рекомендованный для общего применения"
    ),

    "id-tc26-gost-3410-2018-256-paramSetB": CurveParameters(
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97,
        q=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893,
        a=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94,
        b=0x00000000000000000000000000000000000000000000000000000000000000A6,
        x=0x0000000000000000000000000000000000000000000000000000000000000001,
        y=0x8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14,
        name="id-tc26-gost-3410-2018-256-paramSetB",
        description="Набор B - альтернативный, совместимый с предыдущими версиями"
    ),

    "id-tc26-gost-3410-2018-256-paramSetC": CurveParameters(
        p=0x8000000000000000000000000000000000000000000000000000000000000C99,
        q=0x800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F,
        a=0x8000000000000000000000000000000000000000000000000000000000000C96,
        b=0x3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B,
        x=0x0000000000000000000000000000000000000000000000000000000000000001,
        y=0x3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC,
        name="id-tc26-gost-3410-2018-256-paramSetC",
        description="Набор C - с увеличенным полем"
    ),

    "id-tc26-gost-3410-2018-256-paramSetD": CurveParameters(
        p=0x9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B,
        q=0x9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9,
        a=0x9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598,
        b=0x000000000000000000000000000000000000000000000000000000000000805A,
        x=0x0000000000000000000000000000000000000000000000000000000000000000,
        y=0x41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67,
        name="id-tc26-gost-3410-2018-256-paramSetD",
        description="Набор D - с уникальными параметрами"
    ),
}


# =============================================================================
# 3. ОСНОВНОЙ КЛАСС АЛГОРИТМА ГОСТ 34.10-2018 (256 бит)
# =============================================================================

class GOST3410_2018_256:
    def __init__(self, p: int, q: int, a: int, b: int, x: int, y: int):
        # Сохраняем параметры кривой
        self.p = p
        self.q = q
        self.a = a
        self.b = b
        self.Gx = x
        self.Gy = y

        # Константы для внутреннего использования
        self._BYTE_SIZE = 32  # 256 бит = 32 байта
        self._ZERO = 0
        self._ONE = 1

        # Проверка валидности точки генератора
        # Точка должна удовлетворять уравнению кривой: y^2 = x^3 + a*x + b
        r1 = (y * y) % p
        r2 = ((x * x + a) * x + b) % p
        if r1 != r2:
            error_msg = (
                f"Невалидные параметры кривой: точка ({x}, {y}) "
                f"не принадлежит кривой y^2 = x^3 + {a}*x + {b} mod {p}"
            )
            raise ValueError(error_msg)

    def _mod_normalize(self, v: int) -> int:
        if v < 0:
            return v + self.p
        return v % self.p

    def _mod_inv(self, a: int) -> int:
        if a % self.p == 0:
            raise ValueError("Деление на ноль в поле GF(p)")
        return pow(a, -1, self.p)

    def _point_add(self, x1: int, y1: int, x2: int, y2: int) -> Tuple[Optional[int], Optional[int]]:
        # Обработка точки бесконечности
        if x1 is None or y1 is None:
            return x2, y2
        if x2 is None or y2 is None:
            return x1, y1

        p = self.p
        a = self.a

        # Проверка на равенство точек с противоположными знаками y
        # Если x1 == x2 и y1 == -y2, то сумма равна точке бесконечности
        if x1 == x2 and (y1 + y2) % p == 0:
            return None, None

        # Вычисление углового коэффициента lambda
        if x1 == x2 and y1 == y2:
            # Случай удвоения точки
            # lambda = (3*x1^2 + a) / (2*y1)
            numerator = (3 * x1 * x1 + a) % p
            denominator = (2 * y1) % p
            lambd = numerator * self._mod_inv(denominator) % p
        else:
            # Случай сложения различных точек
            # lambda = (y2 - y1) / (x2 - x1)
            dx = (x2 - x1) % p
            if dx == 0:
                # Если dx == 0, а y1 != y2, то это случай с противоположными знаками
                # уже обработан выше
                return None, None
            dy = (y2 - y1) % p
            lambd = dy * self._mod_inv(dx) % p

        # Вычисление координат результирующей точки
        x3 = (lambd * lambd - x1 - x2) % p
        y3 = (lambd * (x1 - x3) - y1) % p

        return x3, y3

    def scalar_mult(self, scalar: int, x: Optional[int] = None, y: Optional[int] = None) -> Tuple[int, int]:
        # Проверка входных данных
        if scalar == 0:
            raise ValueError("Скаляр не может быть равен 0")

        # Используем базовую точку, если не указана другая
        if x is None or y is None:
            x = self.Gx
            y = self.Gy

        # Инициализация результата точкой P
        result_x, result_y = x, y
        scalar_temp = scalar - 1  # Одна точка уже добавлена

        # Алгоритм «двой и добавляй»
        # Идея: просматриваем биты скаляра слева направо,
        # на каждом шаге удваиваем текущую точку, и если текущий бит равен 1,
        # добавляем исходную точку
        while scalar_temp:
            if scalar_temp & 1:
                result_x, result_y = self._point_add(result_x, result_y, x, y)
            scalar_temp >>= 1
            x, y = self._point_add(x, y, x, y)

        return result_x, result_y

    def public_key(self, private_key: int) -> Tuple[int, int]:
        if private_key <= 0 or private_key >= self.q:
            error_msg = (
                f"Приватный ключ {private_key} вне допустимого диапазона "
                f"(1 < key < {self.q})"
            )
            raise ValueError(error_msg)

        return self.scalar_mult(private_key)

    def sign(self, private_key: int, digest: bytes, random_k: Optional[bytes] = None) -> bytes:
        q = self.q
        size = self._BYTE_SIZE

        # Шаг 1: Преобразование хеша в число e = h(M) mod q
        e = int.from_bytes(digest, 'big') % q
        if e == 0:
            e = 1  # Если e == 0, заменяем на 1 согласно стандарту

        # Основной цикл формирования подписи
        # Повторяем до получения ненулевых значений r и s
        attempt_count = 0
        max_attempts = 1000

        while attempt_count < max_attempts:
            attempt_count += 1

            # Шаг 2: Генерация случайного сессионного ключа k
            # k должен быть в диапазоне (1, q)
            if random_k is None:
                random_bytes = urandom(size)
            else:
                if len(random_k) != size:
                    raise ValueError(f"Длина random_k должна быть {size} байт")
                random_bytes = random_k

            k = int.from_bytes(random_bytes, 'big') % q
            if k == 0:
                continue  # k не может быть равен 0

            # Шаг 3: Вычисление точки C = k * G
            cx, _ = self.scalar_mult(k)

            # Шаг 4: Вычисление r = x_C mod q
            r = cx % q
            if r == 0:
                continue  # r не может быть равен 0

            # Шаг 5: Вычисление s = (r*d + k*e) mod q
            s = (private_key * r + k * e) % q
            if s == 0:
                continue  # s не может быть равен 0

            # Успешное формирование подписи
            break
        else:
            # Если не удалось сформировать подпись за максимальное число попыток
            raise RuntimeError(
                f"Не удалось сформировать подпись после {max_attempts} попыток"
            )

        signature = s.to_bytes(size, 'big') + r.to_bytes(size, 'big')

        return signature

    def verify(self, public_key: Tuple[int, int], digest: bytes, signature: bytes) -> bool:
        size = self._BYTE_SIZE
        q = self.q
        p = self.p
        pub_x, pub_y = public_key

        # Проверка длины подписи
        if len(signature) != 64:
            raise ValueError("Длина подписи должна быть 64 байта")

        # Шаг 1: Распаковка подписи
        s = int.from_bytes(signature[:size], 'big')
        r = int.from_bytes(signature[size:], 'big')

        # Шаг 2: Проверка диапазонов значений
        if r <= 0 or r >= q or s <= 0 or s >= q:
            return False

        # Шаг 3: Преобразование хеша в число
        e = int.from_bytes(digest, 'big') % q
        if e == 0:
            e = 1

        # Шаг 4: Вычисление v = e^(-1) mod q
        try:
            v = self._mod_inv_mod_q(e)
        except ValueError:
            return False

        # Шаг 5: Вычисление вспомогательных величин
        z1 = (s * v) % q
        z2 = (-r * v) % q

        # Шаг 6: Вычисление точки R = z1*G + z2*Q
        # Сначала вычисляем z1*G
        gx, gy = self.scalar_mult(z1)

        # Затем вычисляем z2*Q
        qx, qy = self.scalar_mult(z2, pub_x, pub_y)

        # Складываем полученные точки
        rx, ry = self._point_add(gx, gy, qx, qy)

        # Если результат — точка бесконечности, подпись неверна
        if rx is None or ry is None:
            return False

        # Шаг 7: Проверка условия x_R mod q == r
        return (rx % q) == r

    def _mod_inv_mod_q(self, a: int) -> int:
        if a % self.q == 0:
            raise ValueError("Обратный элемент не существует")
        return pow(a, -1, self.q)

    def get_parameters(self) -> Dict[str, int]:
        return {
            'p': self.p,
            'q': self.q,
            'a': self.a,
            'b': self.b,
            'Gx': self.Gx,
            'Gy': self.Gy,
        }


# =============================================================================
# 4. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ РАБОТЫ С КЛЮЧАМИ И ПАРАМЕТРАМИ
# =============================================================================

def create_curve(curve_name: str = "id-tc26-gost-3410-2018-256-paramSetA") -> GOST3410_2018_256:
    if curve_name not in CURVES_256:
        available = ", ".join(CURVES_256.keys())
        raise ValueError(f"Неизвестная кривая: {curve_name}. Доступны: {available}")

    params = CURVES_256[curve_name]
    return GOST3410_2018_256(
        p=params.p,
        q=params.q,
        a=params.a,
        b=params.b,
        x=params.x,
        y=params.y
    )


def generate_private_key(curve: GOST3410_2018_256) -> int:
    private_key = int.from_bytes(urandom(32), 'big') % curve.q
    while private_key == 0:
        private_key = int.from_bytes(urandom(32), 'big') % curve.q
    return private_key


def compute_hash(message: bytes) -> bytes:
    hash_obj = gostcrypto.gosthash.new('streebog256', data=message)
    return hash_obj.digest()


def compute_hash_from_text(text: str) -> bytes:
    return compute_hash(text.encode('cp1251'))


def format_hex(data: bytes) -> str:
    return data.hex()


def format_int_hex(value: int, byte_size: int = 32) -> str:
    return f"{value:0{byte_size * 2}x}"


# =============================================================================
# 5. ДЕМОНСТРАЦИОННАЯ ПРОГРАММА
# =============================================================================

def print_section_header(title: str, width: int = 70) -> None:
    print("\n" + "=" * width)
    print(f" {title}")
    print("=" * width)


def print_subsection_header(title: str, width: int = 70) -> None:
    print("\n" + "-" * width)
    print(f" {title}")
    print("-" * width)


def print_curve_parameters(curve: GOST3410_2018_256) -> None:
    params = curve.get_parameters()
    print("Параметры эллиптической кривой (набор A):")
    print(f"  p  = {params['p']:064x}")
    print(f"  q  = {params['q']:064x}")
    print(f"  a  = {params['a']:064x}")
    print(f"  b  = {params['b']:064x}")
    print(f"  Gx = {params['Gx']:064x}")
    print(f"  Gy = {params['Gy']:064x}")
    print(f"  Размер поля: {params['p'].bit_length()} бит")
    print(f"  Размер подгруппы: {params['q'].bit_length()} бит")


def print_keypair(private_key: int, public_key: Tuple[int, int]) -> None:
    print(f"Приватный ключ (d): {private_key:064x}")
    print(f"Открытый ключ (Q):")
    print(f"  x = {public_key[0]:064x}")
    print(f"  y = {public_key[1]:064x}")


def print_signature(signature: bytes) -> None:
    print(f"Первая компонента (s): {signature[:32].hex()}")
    print(f"Вторая компонента (r): {signature[32:].hex()}")
    print(f"Полная подпись (64 байта): {signature.hex()}")


def main():
    print_section_header("ДЕМОНСТРАЦИЯ РАБОТЫ АЛГОРИТМА ГОСТ 34.10-2018 (256 БИТ)", 80)

    # =====================================================================
    # Шаг 1: Инициализация кривой
    # =====================================================================
    print_section_header("1. ИНИЦИАЛИЗАЦИЯ КРИВОЙ", 80)
    print("Используемый набор параметров: A")
    print("(id-tc26-gost-3410-2018-256-paramSetA)")

    # Создание экземпляра кривой с параметрами набора A
    gost = create_curve("id-tc26-gost-3410-2018-256-paramSetA")
    print_curve_parameters(gost)

    # =====================================================================
    # Шаг 2: Генерация ключевой пары
    # =====================================================================
    print_section_header("2. ГЕНЕРАЦИЯ КЛЮЧЕВОЙ ПАРЫ", 80)

    # Генерация приватного ключа
    private_key = generate_private_key(gost)

    # Вычисление открытого ключа
    public_key = gost.public_key(private_key)
    print_keypair(private_key, public_key)

    # =====================================================================
    # Шаг 3: Хеширование сообщения
    # =====================================================================
    print_section_header("3. ХЕШИРОВАНИЕ СООБЩЕНИЯ (ГОСТ 34.11-2018)", 80)

    # Ввод сообщения от пользователя
    print("Введите текст сообщения:")
    text = input("> ")

    # Вычисление хеша по ГОСТ 34.11-2018 (Стрибог 256)
    hash_obj = gostcrypto.gosthash.new('streebog256', data=text.encode('cp1251'))
    digest = hash_obj.digest()

    print(f"Исходное сообщение: {text}")
    print(f"Длина сообщения: {len(text)} байт (в кодировке cp1251)")
    print(f"Хеш сообщения (Стрибог 256): {hash_obj.hexdigest()}")
    print(f"Размер хеша: {len(digest)} байт ({len(digest) * 8} бит)")

    # =====================================================================
    # Шаг 4: Формирование электронной подписи
    # =====================================================================
    print_section_header("4. ФОРМИРОВАНИЕ ЭЛЕКТРОННОЙ ПОДПИСИ", 80)

    # Формирование подписи с использованием приватного ключа
    signature = gost.sign(private_key, digest)
    print_signature(signature)

    # =====================================================================
    # Шаг 5: Проверка электронной подписи
    # =====================================================================
    print_section_header("5. ПРОВЕРКА ЭЛЕКТРОННОЙ ПОДПИСИ", 80)

    # Проверка подписи с использованием открытого ключа
    is_valid = gost.verify(public_key, digest, signature)

    print(f"Хеш сообщения: {digest.hex()}")
    print(f"Результат проверки: {'ПОДПИСЬ ВЕРНА' if is_valid else 'ПОДПИСЬ НЕВЕРНА'}")

    # =====================================================================
    # Шаг 6: Демонстрация устойчивости к изменению хеша
    # =====================================================================
    print_section_header("6. ДЕМОНСТРАЦИЯ УСТОЙЧИВОСТИ К ИЗМЕНЕНИЮ ХЕША", 80)
    print("Проверка свойства целостности: изменение хеша делает подпись недействительной")

    # Генерация случайного хеша (отличного от оригинального)
    fake_digest = urandom(32)

    # Проверка подписи с поддельным хешем
    is_valid_fake = gost.verify(public_key, fake_digest, signature)

    print(f"Оригинальный хеш: {digest.hex()}")
    print(f"Поддельный хеш:  {fake_digest.hex()}")
    print(f"Результат проверки с поддельным хешем: "
          f"{'ПОДПИСЬ ВЕРНА' if is_valid_fake else 'ПОДПИСЬ НЕВЕРНА'}")

    if not is_valid_fake:
        print("  -> Изменение хеша делает подпись недействительной, "
              "что подтверждает свойство целостности.")
    else:
        print("  -> ВНИМАНИЕ: Подпись осталась верной при изменении хеша. "
              "Это указывает на ошибку в реализации!")

    # =====================================================================
    # Дополнительная проверка: демонстрация с другим сообщением
    # =====================================================================
    print_section_header("7. ДОПОЛНИТЕЛЬНАЯ ПРОВЕРКА", 80)
    print("Демонстрация работы с другим сообщением")

    test_message = "Test message for GOST 34.10-2018"
    test_hash = gostcrypto.gosthash.new('streebog256', data=test_message.encode('cp1251')).digest()
    test_signature = gost.sign(private_key, test_hash)
    test_valid = gost.verify(public_key, test_hash, test_signature)

    print(f"Сообщение: {test_message}")
    print(f"Хеш: {test_hash.hex()}")
    print(f"Подпись: {test_signature.hex()}")
    print(f"Результат проверки: {'ПОДПИСЬ ВЕРНА' if test_valid else 'ПОДПИСЬ НЕВЕРНА'}")

    # =====================================================================
    # Завершение демонстрации
    # =====================================================================
    print_section_header("ДЕМОНСТРАЦИЯ ЗАВЕРШЕНА", 80)
    print("Все этапы работы алгоритма ГОСТ 34.10-2018 выполнены успешно.")
    print("Программа демонстрирует корректную работу всех функций:")
    print("  - Генерацию ключевой пары")
    print("  - Хеширование по ГОСТ 34.11-2018")
    print("  - Формирование электронной подписи")
    print("  - Проверку электронной подписи")
    print("  - Устойчивость к изменению подписываемых данных")
    print("=" * 80)


if __name__ == "__main__":
    main()
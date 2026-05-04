"""
Эллиптическая криптография - математические функции
Оптимизировано для работы с большими числами (ГОСТ 34.10-2018)
"""

from math import isqrt
from typing import Optional, Tuple, Union


# Типы для точек
Point = Tuple[int, int]
PointOrInf = Union[Point, str]


def to_upper_index(num: int | str, sign: str = '') -> str:
    """Преобразование числа в верхний индекс для вывода"""
    sign = sign.replace('-', '⁻') if '-' in sign else ''
    str_num = sign + str(num)
    upper_index_digits = {
        '-': '⁻', '0': '⁰', '1': '¹', '2': '²', '3': '³',
        '4': '⁴', '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'
    }
    return ''.join(upper_index_digits[d] for d in str_num)


def to_lower_index(num: int | str, sign: str = '') -> str:
    """Преобразование числа в нижний индекс для вывода"""
    sign = sign.replace('-', '₋') if '-' in sign else ''
    str_num = sign + str(num)
    lower_index_digits = {
        '-': '₋', '0': '₀', '1': '₁', '2': '₂', '3': '₃',
        '4': '₄', '5': '₅', '6': '₆', '7': '₇', '8': '₈', '9': '₉'
    }
    return ''.join(lower_index_digits[d] for d in str_num)


def mod_inverse(a: int, m: int) -> int:
    """
    Расширенный алгоритм Евклида для нахождения обратного элемента
    a^(-1) mod m (m должно быть простым или взаимно простым с a)
    """
    a = a % m
    if a == 0:
        raise ValueError(f"Нет обратного элемента для {a} mod {m}")
    
    # Используем встроенную функцию Python (самую быструю)
    return pow(a, -1, m)


def mod_sqrt(a: int, p: int) -> Optional[int]:
    """
    Квадратный корень по модулю простого числа p
    Алгоритм Тонелли-Шенкса
    """
    a %= p
    
    if a == 0:
        return 0
    
    # Проверка существования корня (символ Лежандра)
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    
    # Случай p ≡ 3 (mod 4)
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    
    # Алгоритм Тонелли-Шенкса для p ≡ 1 (mod 4)
    # Разложение p-1 = Q * 2^S
    Q = p - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2
        S += 1
    
    # Поиск квадратичного невычета z
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    
    M = S
    c = pow(z, Q, p)
    t = pow(a, Q, p)
    R = pow(a, (Q + 1) // 2, p)
    
    while t != 1:
        # Находим наименьшее i, где t^(2^i) ≡ 1
        t2i = t
        for i in range(1, M):
            t2i = (t2i * t2i) % p
            if t2i == 1:
                break
        
        b = pow(c, 1 << (M - i - 1), p)
        M = i
        c = (b * b) % p
        t = (t * c) % p
        R = (R * b) % p
    
    return R


def is_point_on_curve(x: int, y: int, a: int, b: int, mod: int) -> bool:
    """
    Проверяет, лежит ли точка на эллиптической кривой
    y² ≡ x³ + a·x + b (mod mod)
    """
    left = pow(y, 2, mod)
    right = (pow(x, 3, mod) + a * x + b) % mod
    return left == right


def generate_random_point(a: int, b: int, mod: int, max_attempts: int = 1000) -> Optional[Point]:
    """
    Генерирует случайную точку на эллиптической кривой
    """
    import random
    
    for _ in range(max_attempts):
        x = random.randrange(mod)
        right_side = (pow(x, 3, mod) + a * x + b) % mod
        y = mod_sqrt(right_side, mod)
        if y is not None:
            return (x, y)
    
    return None


def point_double(point: Point, a: int, mod: int, print_mode: bool = False) -> PointOrInf:
    """
    Удвоение точки на эллиптической кривой
    2P = (x₃, y₃)
    """
    x, y = point
    
    if y == 0:
        return "O"
    
    # λ = (3x² + a) / (2y)
    numerator = (3 * pow(x, 2, mod) + a) % mod
    denominator_inv = mod_inverse(2 * y, mod)
    lmbd = (numerator * denominator_inv) % mod
    
    if print_mode:
        print(f"λ = (3·{x}² + {a}) / (2·{y}) = {numerator} * {denominator_inv} = {lmbd} (mod {mod})")
    
    # x₃ = λ² - 2x
    x3 = (pow(lmbd, 2, mod) - 2 * x) % mod
    
    # y₃ = λ·(x - x₃) - y
    y3 = (lmbd * (x - x3) - y) % mod
    
    if print_mode:
        print(f"2P = ({x3}, {y3})")
    
    return (x3, y3)


def point_add(P: PointOrInf, Q: PointOrInf, a: int, mod: int, print_mode: bool = False) -> PointOrInf:
    """
    Сложение двух точек на эллиптической кривой
    """
    # Обработка бесконечно удалённой точки
    if P == "O":
        return Q
    if Q == "O":
        return P
    
    x1, y1 = P
    x2, y2 = Q
    
    # P = -Q (противоположные точки)
    if x1 == x2 and (y1 + y2) % mod == 0:
        if print_mode:
            print("Точки противоположны: P + Q = O")
        return "O"
    
    # P = Q (удвоение)
    if P == Q:
        return point_double(P, a, mod, print_mode)
    
    # λ = (y₂ - y₁) / (x₂ - x₁)
    numerator = (y2 - y1) % mod
    denominator_inv = mod_inverse((x2 - x1) % mod, mod)
    lmbd = (numerator * denominator_inv) % mod
    
    if print_mode:
        print(f"λ = (y₂ - y₁)/(x₂ - x₁) = {numerator} * {denominator_inv} = {lmbd} (mod {mod})")
    
    # x₃ = λ² - x₁ - x₂
    x3 = (pow(lmbd, 2, mod) - x1 - x2) % mod
    
    # y₃ = λ·(x₁ - x₃) - y₁
    y3 = (lmbd * (x1 - x3) - y1) % mod
    
    if print_mode:
        print(f"P + Q = ({x3}, {y3})")
    
    return (x3, y3)


def scalar_multiply(k: int, point: Point, a: int, mod: int, print_mode: bool = False) -> PointOrInf:
    """
    Умножение точки на скаляр (бинарный алгоритм)
    k·P = P + P + ... + P (k раз)
    """
    if point == "O" or k == 0:
        return "O"
    
    if k < 0:
        # k отрицательное: k·P = (-k)·(-P)
        raise ValueError("Отрицательные скаляры не поддерживаются")
    
    if print_mode:
        print(f"\nВычисление {k}·P = {k} * {point}")
        print(f"Двоичное представление: {bin(k)[2:]}")
    
    result = "O"
    addend = point
    
    # Двоичный алгоритм "double-and-add"
    for bit in bin(k)[2:]:
        # Удвоение
        if print_mode:
            print(f"\n  Удвоение: {addend} -> ", end="")
        addend = point_double(addend, a, mod, print_mode=False)
        if print_mode:
            print(addend)
        
        # Если бит = 1, добавляем исходную точку
        if bit == '1':
            if print_mode:
                print(f"  Бит=1, добавляем P: {result} + {point} = ", end="")
            result = point_add(result, point, a, mod, print_mode=False)
            if print_mode:
                print(result)
    
    return result


def point_negate(point: PointOrInf, mod: int) -> PointOrInf:
    """Возвращает противоположную точку -P = (x, -y mod mod)"""
    if point == "O":
        return "O"
    x, y = point
    return (x, (-y) % mod)


def is_prime(n: int) -> bool:
    """Проверка числа на простоту (для малых чисел)"""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    
    # Проверка делителей до sqrt(n)
    for i in range(3, isqrt(n) + 1, 2):
        if n % i == 0:
            return False
    return True


def baby_step_giant_step(point: Point, a: int, mod: int, order_max: int) -> int:
    """
    Алгоритм "шаг младенца - шаг великана" для нахождения порядка точки
    """
    from math import ceil, sqrt
    
    m = ceil(sqrt(order_max))
    
    # Таблица младенческих шагов: j*P
    baby_steps = {}
    current = "O"
    
    for j in range(m):
        if current != "O":
            baby_steps[current] = j
        current = point_add(current, point, a, mod)
    
    # Вычисляем Q = -m·P
    mP = scalar_multiply(m, point, a, mod)
    if mP == "O":
        return m
    Q = point_negate(mP, mod)
    
    # Гигантские шаги
    current = Q
    for i in range(m):
        if current in baby_steps:
            order = i * m + baby_steps[current]
            # Проверяем, что это действительно порядок
            if scalar_multiply(order, point, a, mod) == "O":
                return order
        current = point_add(current, Q, a, mod)
    
    return order_max


def init_curve_fast() -> Tuple[int, int, int]:
    """
    Инициализация для ГОСТ 34.10-2018 - не генерируем все точки
    """
    a, b, mod = map(int, input("Введите коэффициенты кривой a, b и модуль >> ").split())
    
    print(f"\nУравнение кривой: y² = x³ + {a}x + {b} (mod {mod})\n")
    
    if not is_prime(mod):
        print(f"Внимание: {mod} не является простым числом! Операции могут работать некорректно.")
    
    return a, b, mod
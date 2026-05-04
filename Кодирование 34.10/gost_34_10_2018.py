"""
ГОСТ Р 34.10-2018 - Электронная подпись на эллиптических кривых
Оптимизированная версия для криптографических размеров чисел
"""

import hashlib
import random
from elliptic_math import (
    mod_inverse, init_curve_fast, generate_random_point, is_point_on_curve,
    point_add, point_double, scalar_multiply, to_lower_index, is_prime
)


def hash_to_int(message: str, q: int) -> int:
    """
    Хэширование сообщения по ГОСТ Р 34.10-2018
    Используется SHA-256
    """
    h = hashlib.sha256(message.encode('utf-8')).digest()
    h_int = int.from_bytes(h, byteorder='big')
    return h_int % q


def generate_random_k(q: int) -> int:
    """Генерация случайного k (1 < k < q)"""
    return random.randint(2, q - 1)


def get_point_order(point, a: int, mod: int, max_order: int, print_mode: bool = False) -> int:
    """
    Нахождение порядка точки на эллиптической кривой
    Использует алгоритм "шаг младенца - шаг великана"
    """
    from math import ceil, sqrt
    
    if point == "O":
        return 1
    
    m = ceil(sqrt(max_order))
    
    if print_mode:
        print(f"\nПоиск порядка точки {point}")
        print(f"m = ⌈√{max_order}⌉ = {m}")
    
    # Таблица младенческих шагов
    baby_steps = {}
    current = "O"
    
    for j in range(m):
        if current != "O":
            baby_steps[current] = j
        current = point_add(current, point, 0, mod, print_mode=False)
    
    # Вычисляем Q = -m·P
    mP = scalar_multiply(m, point, a, mod, print_mode=False)
    if mP == "O":
        return m
    
    # Противоположная точка
    if mP != "O":
        Q = (mP[0], (-mP[1]) % mod)
    else:
        Q = "O"
    
    # Гигантские шаги
    current = Q
    for i in range(m):
        if current in baby_steps:
            order = i * m + baby_steps[current]
            # Проверяем порядок
            test = scalar_multiply(order, point, a, mod, print_mode=False)
            if test == "O":
                if print_mode:
                    print(f"Найден порядок: {order}")
                return order
        current = point_add(current, Q, 0, mod, print_mode=False)
    
    return max_order


def generate_key_pair(base_point, curve_coeff: int, mod: int, q: int, print_mode: bool = True):
    """
    Генерация пары ключей (секретный и открытый)
    Возвращает: (d, Q) где d - секретный ключ, Q - открытый ключ
    """
    if print_mode:
        print("\n" + "=" * 60)
        print("ГЕНЕРАЦИЯ КЛЮЧЕЙ")
        print("=" * 60)
    
    # Генерация секретного ключа (1 < d < q)
    d = random.randint(2, q - 2)
    if print_mode:
        print(f"Секретный ключ d = {d}")
    
    # Вычисление открытого ключа Q = d·P
    Q = scalar_multiply(d, base_point, curve_coeff, mod, print_mode=False)
    
    if print_mode:
        print(f"Открытый ключ Q = {Q}")
    
    return d, Q


def gost_sign(message: str, d: int, curve_coeff: int, mod: int,
              base_point, q: int, print_mode: bool = True):
    """
    Формирование электронной подписи по ГОСТ Р 34.10-2018
    
    Возвращает: (r, s) - подпись
    """
    if print_mode:
        print("\n" + "=" * 60)
        print("ФОРМИРОВАНИЕ ЭЛЕКТРОННОЙ ПОДПИСИ (ГОСТ Р 34.10-2018)")
        print("=" * 60)
        print(f"Сообщение: {message}")
        print(f"Секретный ключ d = {d}")
        print(f"Базовая точка P = {base_point}")
        print(f"Порядок точки q = {q}")
    
    # Шаг 1: Хэш сообщения
    e = hash_to_int(message, q)
    if print_mode:
        print(f"\n1. Хэш сообщения e = H(M) mod q = {e}")
    
    if e == 0:
        e = 1
        if print_mode:
            print(f"   e = 0, принимаем e = 1")
    
    # Шаги 2-5: Генерация подписи
    max_attempts = 100
    for attempt in range(max_attempts):
        # Шаг 2: Случайное k
        k = generate_random_k(q)
        if print_mode:
            print(f"\n2. Случайное число k = {k}")
        
        # Шаг 3: R = k·P
        R = scalar_multiply(k, base_point, curve_coeff, mod, print_mode=False)
        if print_mode:
            print(f"3. R = k·P = {R}")
        
        if R == "O":
            if print_mode:
                print("   R = O, выбираем другое k")
            continue
        
        # Шаг 4: r = x_R mod q
        r = R[0] % q
        if print_mode:
            print(f"4. r = x_R mod q = {r}")
        
        if r == 0:
            if print_mode:
                print("   r = 0, выбираем другое k")
            continue
        
        # Шаг 5: s = (r·d + k·e) mod q
        s = (r * d + k * e) % q
        if print_mode:
            print(f"5. s = (r·d + k·e) mod q = {s}")
        
        if s == 0:
            if print_mode:
                print("   s = 0, выбираем другое k")
            continue
        
        if print_mode:
            print(f"\n✓ Подпись сформирована: (r, s) = ({r}, {s})")
        
        return (r, s)
    
    raise RuntimeError("Не удалось сформировать подпись после {max_attempts} попыток")


def gost_verify(message: str, signature, Q, curve_coeff: int,
                mod: int, base_point, q: int, print_mode: bool = True) -> bool:
    """
    Проверка электронной подписи по ГОСТ Р 34.10-2018
    """
    r, s = signature
    
    if print_mode:
        print("\n" + "=" * 60)
        print("ПРОВЕРКА ЭЛЕКТРОННОЙ ПОДПИСИ (ГОСТ Р 34.10-2018)")
        print("=" * 60)
        print(f"Сообщение: {message}")
        print(f"Подпись: (r, s) = ({r}, {s})")
        print(f"Открытый ключ Q = {Q}")
        print(f"Базовая точка P = {base_point}")
        print(f"Порядок точки q = {q}")
    
    # Шаг 1: Проверка r и s
    if not (0 < r < q):
        if print_mode:
            print(f"\n✗ Ошибка: r = {r} не в интервале (0, {q})")
        return False
    
    if not (0 < s < q):
        if print_mode:
            print(f"\n✗ Ошибка: s = {s} не в интервале (0, {q})")
        return False
    
    if print_mode:
        print("\n1. Проверка r и s: OK")
    
    # Шаг 2: Хэш сообщения
    e = hash_to_int(message, q)
    if print_mode:
        print(f"\n2. Хэш сообщения e = H(M) mod q = {e}")
    
    if e == 0:
        e = 1
        if print_mode:
            print(f"   e = 0, принимаем e = 1")
    
    # Шаг 3: v = e⁻¹ mod q
    try:
        v = mod_inverse(e, q)
        if print_mode:
            print(f"\n3. v = e⁻¹ mod q = {v}")
    except ValueError:
        if print_mode:
            print(f"\n✗ Ошибка: невозможно найти обратный элемент для e = {e}")
        return False
    
    # Шаг 4: u₁ = s·v mod q, u₂ = -r·v mod q
    u1 = (s * v) % q
    u2 = ((-r) % q * v) % q
    
    if print_mode:
        print(f"\n4. u₁ = s·v mod q = {u1}")
        print(f"   u₂ = -r·v mod q = {u2}")
    
    # Шаг 5: C = u₁·P + u₂·Q
    if print_mode:
        print(f"\n5. Вычисление C = u₁·P + u₂·Q:")
    
    u1P = scalar_multiply(u1, base_point, curve_coeff, mod, print_mode=False)
    if print_mode:
        print(f"   u₁·P = {u1P}")
    
    u2Q = scalar_multiply(u2, Q, curve_coeff, mod, print_mode=False)
    if print_mode:
        print(f"   u₂·Q = {u2Q}")
    
    C = point_add(u1P, u2Q, curve_coeff, mod, print_mode=False)
    if print_mode:
        print(f"   C = {C}")
    
    # Шаг 6: Проверка
    if C == "O":
        if print_mode:
            print("\n✗ Подпись НЕВЕРНА: C = O")
        return False
    
    xC = C[0] % q
    if print_mode:
        print(f"\n6. xC mod q = {xC}")
    
    if xC == r:
        if print_mode:
            print("\n✓ Подпись ВЕРНА!")
        return True
    else:
        if print_mode:
            print(f"\n✗ Подпись НЕВЕРНА: xC = {xC} ≠ r = {r}")
        return False


def get_base_point(a: int, b: int, mod: int, print_mode: bool = True):
    """
    Получение базовой точки (генератора)
    """
    if print_mode:
        print("\n" + "=" * 60)
        print("ВЫБОР БАЗОВОЙ ТОЧКИ (ГЕНЕРАТОРА)")
        print("=" * 60)
    
    # Для криптографических размеров используем стандартные параметры
    # ГОСТ Р 34.10-2018 имеет стандартные кривые
    
    # Вариант 1: ручной ввод
    choice = input("Выбрать стандартную точку ГОСТ? (y/n): ")
    
    if choice.lower() == 'y':
        # Стандартные параметры для кривой id-GostR3410-2018-256
        # p = 57896044618658097711785492504343953926634992332820282019728792003956564819941
        # a = 7, b = 5
        # Генератор задаётся координатами
        x0 = 2
        y0 = 4015598787972977651300098959095686301245230113408808269215641260346139734171
        point = (x0, y0)
        
        # Проверяем, что точка лежит на кривой
        if is_point_on_curve(x0, y0, a, b, mod):
            if print_mode:
                print(f"\nИспользуем стандартную точку: {point}")
            return point
    
    # Вариант 2: поиск случайной точки
    if print_mode:
        print("\nГенерация случайной точки на кривой...")
    
    point = generate_random_point(a, b, mod)
    if point is None:
        raise ValueError("Не удалось найти ни одной точки на кривой")
    
    if print_mode:
        print(f"Найдена точка: {point}")
    
    return point


def main():
    """Основная функция - демонстрация работы ГОСТ Р 34.10-2018"""
    print("\n" + "=" * 60)
    print("РЕАЛИЗАЦИЯ ГОСТ Р 34.10-2018 (ЭЛЕКТРОННАЯ ПОДПИСЬ)")
    print("=" * 60)
    
    # Ввод параметров кривой
    print("\nВведите параметры эллиптической кривой:")
    print("Формат: a b p (коэффициенты кривой и модуль)")
    print("Пример для ГОСТ: 7 5 57896044618658097711785492504343953926634992332820282019728792003956564819941")
    
    a, b, mod = init_curve_fast()
    
    # Получение базовой точки
    P = get_base_point(a, b, mod)
    
    # Определение порядка базовой точки
    # Для криптографических размеров порядок обычно стандартизирован
    print("\nОпределение порядка базовой точки...")
    
    # Используем приблизительный порядок (можно уточнить через алгоритм)
    approximate_order = mod + 1
    q = get_point_order(P, a, mod, approximate_order, print_mode=False)
    
    print(f"Порядок базовой точки (q) = {q}")
    
    # Убеждаемся, что q простое
    if is_prime(q):
        print("q - простое число ✓")
    else:
        print("Внимание: q не является простым!")
    
    # Генерация ключей
    d, Q = generate_key_pair(P, a, mod, q)
    
    # Цикл работы с подписями
    while True:
        print("\n" + "=" * 60)
        print("ВЫБЕРИТЕ ДЕЙСТВИЕ:")
        print("1 - Подписать сообщение")
        print("2 - Проверить подпись")
        print("3 - Сгенерировать новую пару ключей")
        print("4 - Выйти")
        
        choice = input("\nВаш выбор: ")
        
        if choice == '1':
            message = input("Введите сообщение для подписи: ")
            r, s = gost_sign(message, d, a, mod, P, q)
            print(f"\nРезультат подписи:")
            print(f"r = {r}")
            print(f"s = {s}")
            
            save = input("\nСохранить подпись в файл? (y/n): ")
            if save.lower() == 'y':
                with open("signature.txt", "w") as f:
                    f.write(f"{r}\n{s}\n{message}")
                print("Подпись сохранена в signature.txt")
        
        elif choice == '2':
            use_saved = input("Использовать сохранённую подпись? (y/n): ")
            
            if use_saved.lower() == 'y':
                try:
                    with open("signature.txt", "r") as f:
                        lines = f.readlines()
                        r = int(lines[0].strip())
                        s = int(lines[1].strip())
                        message = lines[2].strip()
                    print(f"Загружено сообщение: {message}")
                    print(f"Загружена подпись: ({r}, {s})")
                except Exception as e:
                    print(f"Ошибка загрузки файла: {e}")
                    continue
            else:
                message = input("Введите сообщение для проверки: ")
                r = int(input("Введите r: "))
                s = int(input("Введите s: "))
            
            is_valid = gost_verify(message, (r, s), Q, a, mod, P, q)
            
            print("\n" + "=" * 60)
            if is_valid:
                print("РЕЗУЛЬТАТ: ПОДПИСЬ ДЕЙСТВИТЕЛЬНА ✓")
            else:
                print("РЕЗУЛЬТАТ: ПОДПИСЬ НЕДЕЙСТВИТЕЛЬНА ✗")
            print("=" * 60)
        
        elif choice == '3':
            d, Q = generate_key_pair(P, a, mod, q)
        
        elif choice == '4':
            print("До свидания!")
            break
        
        else:
            print("Неверный выбор!")


if __name__ == "__main__":
    main()
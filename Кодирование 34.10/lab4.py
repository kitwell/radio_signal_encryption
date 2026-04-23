from re import sub
from math import prod, isqrt

# Для строкового вывода
def to_upper_index(num: int | str, sign: str = '') -> str:
    """
    Функция для представления верхних числовых индексов
    """
    sign = sub(r'[^-]', '', sign)[:1]
    str_num = sign + str(num)
    upper_index_digits = {
        '-': '⁻',
        '0': '⁰',
        '1': '¹',
        '2': '²',
        '3': '³',
        '4': '⁴',
        '5': '⁵',
        '6': '⁶',
        '7': '⁷',
        '8': '⁸',
        '9': '⁹',
    }

    return ''.join([upper_index_digits[digit] for digit in list(str_num)])
def to_lower_index(num: int | str, sign: str = '') -> str:
    """
    Функция для представления нижних числовых индексов
    """
    sign = sub(r'[^-]', '', sign)[:1]
    str_num = sign + str(num)
    lower_index_digits = {
        '-': '₋',
        '0': '₀',
        '1': '₁',
        '2': '₂',
        '3': '₃',
        '4': '₄',
        '5': '₅',
        '6': '₆',
        '7': '₇',
        '8': '₈',
        '9': '₉',
    }

    return ''.join([lower_index_digits[digit] for digit in list(str_num)])


def reverse(basis: int, module: int) -> int:
    """
    Функция для нахождения обратного элемента
    """
    return basis ** (euler_func(module) - 1) % module
def euler_func(num: int) -> int:
    """
    Функция, возвращающая результат функции Эйлера от входного числа
    """
    if num == 1:
        return 1
    return int(num * (prod((1 - 1 / multiplier) for multiplier in set(canon_decomposition(num)))))
def canon_decomposition(num: int, multipliers=None) -> list:
    """
    Функция для канонического разложения входного числа
    """
    if multipliers is None:
        multipliers = list()
    for divider in range(2, isqrt(num) + 1):
        if num % divider == 0:
            num //= divider
            multipliers.append(divider)
            return canon_decomposition(num, multipliers)
    if num > 1:
        multipliers.append(num)
    return multipliers


def init_curve() -> tuple[int, int, int, list[tuple[int, int] | str]]:
    a, b, mod = map(int, input("Введите коэффициенты кривой a, b и значение модуля >> ").split())
    print(f"Уравнение кривой E{to_lower_index(mod)}{a, b}: y{to_upper_index(2)} = "
          f"x{to_upper_index(3)} + {a} × x + {b} (mod {mod})", end="\n\n")

    points = []
    x_coords = []
    y_coords = []

    for coord in range(mod):
        x_coords.append((coord, (coord ** 3 + a * coord + b) % mod))
        y_coords.append((coord, coord ** 2 % mod))

    for x_coord, x_value in x_coords:
        for y_coord, y_value in y_coords:
            if x_value == y_value:
                points.append((x_coord, y_coord))

    print("Группа точек ЭК:", *points, "и точка б.уд.т.O")
    points.append("O")
    print("Порядок ЭК =", len(points), end="\n\n")

    return a, b, mod, points
def choose_point(points: list[tuple[int, int] | str], point_letter: str) -> tuple[int, int] | str:
    def validate_point():
        while True:
            point = input(f"Введите координаты точки {point_letter} >> ").strip()
            try:
                point = tuple(map(int, point.split()))
                return point
            except ValueError:
                if point.upper() == "O":
                    return point.upper()
                else:
                    print("Ошибка при валидации точки!")
            except:
                print("Ошибка при валидации точки!")

    point = validate_point()
    while point not in points:
        print("Такой точки нет среди точек ЭК")
        point = validate_point()
    return point
def summarize_points(first_point: tuple[int, int] | str, second_point: tuple[int, int] | str, mod: int, print_mode=True) \
        -> tuple[int, int] | str:
    """
    Функция для сложения двух точек ЭК над GF(p)
    """
    if print_mode: print("1) P + Q:")
    try:
        x_1, y_1 = first_point
        x_2, y_2 = second_point

        numerator, denominator = y_2 - y_1, x_2 - x_1
        sign = "-" if numerator / denominator < 0 else ""
        if sign:
            if numerator > 0:
                numerator *= -1
            denominator = abs(denominator)

        if print_mode: print(f"λ = (y{to_lower_index(2)} - y{to_lower_index(1)}) / "
                             f"(x{to_lower_index(2)} - x{to_lower_index(1)}) = "
                             f"{sign} ({abs(numerator)} / {denominator}) = "
                             f"{sign} {abs(numerator)} × {denominator}{to_upper_index(1, "-")} ⊜")
        reversed_denominator = reverse(denominator, mod)
        if print_mode: print(f"{denominator}{to_upper_index(1, "-")} (mod {mod}) ≡ "
                             f"{reversed_denominator} (mod {mod})")
        lmbd = numerator * reversed_denominator
        if print_mode: print(f"⊜ {numerator} × {reversed_denominator} = {lmbd}", end=" ≡ ")
        lmbd %= mod
        if print_mode: print(f"{lmbd} (mod {mod})", end="\n\n")

        x_3 = lmbd ** 2 - x_1 - x_2
        if print_mode: print(f"x{to_lower_index(3)} = "
                             f"λ{to_upper_index(2)} - x{to_lower_index(1)} - x{to_lower_index(2)} = {x_3}", end=" ≡ ")
        x_3 %= mod
        if print_mode: print(f"{x_3} (mod {mod})")

        y_3 = lmbd * (x_1 - x_3) - y_1
        if print_mode: print(
            f"y{to_lower_index(3)} = λ × (x{to_lower_index(1)} - x{to_lower_index(3)}) - y{to_lower_index(1)} = {y_3}",
            end=" ≡ ")
        y_3 %= mod
        if print_mode: print(f"{y_3} (mod {mod})", end="\n\n")

        return x_3, y_3
    except ZeroDivisionError:
        return "O"
    except ValueError:
        if first_point == "O":
            return second_point
        elif second_point == "O":
            return first_point
        else:
            return "O"
def double_point(curve_coefficient: int, point: tuple[int, int] | str, mod: int, print_mode=True) -> tuple[int, int] | str:
    """
    Функция для удвоения точки ЭК над GF(p)
    """
    if print_mode: print("2) 2P:")
    try:
        x_1, y_1 = point

        if y_1 == 0:
            return "O"

        numerator, denominator = 3 * x_1 ** 2 + curve_coefficient, 2 * y_1

        if print_mode: print(f"λ = (3 × x{to_lower_index(1)}{to_upper_index(2)} + a) / (2 × y{to_lower_index(1)}) = "
              f"{numerator} / {denominator} = {numerator} × {denominator}{to_upper_index(1, "-")} ⊜")
        reversed_denominator = reverse(denominator, mod)
        if print_mode: print(f"{denominator}{to_upper_index(1, "-")} (mod {mod}) ≡ "
                             f"{reversed_denominator} (mod {mod})")
        lmbd = numerator * reversed_denominator
        if print_mode: print(f"⊜ {numerator} × {reversed_denominator} = {lmbd}", end=" ≡ ")
        lmbd %= mod
        if print_mode: print(f"{lmbd} (mod {mod})", end="\n\n")

        x_4 = lmbd ** 2 - 2 * x_1
        if print_mode: print(f"x{to_lower_index(4)} = λ{to_upper_index(2)} - 2 × x{to_lower_index(1)} = {x_4}",
                             end=" ≡ ")
        x_4 %= mod
        if print_mode: print(f"{x_4} (mod {mod})")

        y_4 = lmbd * (x_1 - x_4) - y_1
        if print_mode: print(
            f"y{to_lower_index(4)} = λ × (x{to_lower_index(1)} - x{to_lower_index(4)}) - y{to_lower_index(1)} = {y_4}",
            end=" ≡ ")
        y_4 %= mod
        if print_mode: print(f"{y_4} (mod {mod})", end="\n\n")

        return x_4, y_4
    except ValueError:
        return "O"


def main() -> None:
    """
    Основная функция
    """
    a, _, mod, points = init_curve()

    p_point = choose_point(points, point_letter="P")
    q_point = choose_point(points, point_letter="Q")
    print(f"{f'P{p_point}' if p_point != "O" else f'P = {p_point}'}, "
          f"{f'Q{q_point}' if q_point != "O" else f'Q = {q_point}'}", end="\n\n")

    if p_point != q_point:
        total = summarize_points(p_point, q_point, mod)
        print(f"P + Q = {f'•{total}' if total != "O" else f'{total}'}", end="\n\n\n")
    duplication = double_point(a, p_point, mod)
    print(f"2P = {f'•{duplication}' if duplication != "O" else f'{duplication}'}")


if __name__ == "__main__":
    main()

from lab4 import to_lower_index, init_curve, choose_point, summarize_points, double_point

def scalar_multiplexer(scalar: int, point: tuple[int, int], curve_coefficient: int, modulo: int, print_mode=True) \
        -> tuple[int, int] | str:
    """
    Функция для скалярного умножения точки кривой
    """
    if point == "O":
        return "O"


    bin_scalar = bin(scalar)[2:]
    if print_mode: print(f"{scalar}{to_lower_index(10)} = {bin_scalar}{to_lower_index(2)}", end="\n\n")

    R = "O"
    if print_mode: print("R = O — б.уд.т.O")
    for bin_digit in bin_scalar:
        if print_mode: print(f"{bin_digit}{to_lower_index(2)}: R = 2R = 2{f'R{R}' if R != "O" else f'{R}'}", end=" = ")
        R = double_point(curve_coefficient, R, modulo, print_mode=False)
        if print_mode: print(f"{f'•{R}' if R != "O" else f'{R}'}")

        if bin_digit == "1":
            if print_mode: print(f"    R = R + P = "
                                 f"{f'R{R}' if R != "O" else f'{R}'} + {f'P{point}' if point != "O" else f'{point}'}",
                                 end=" = ")
            if R == point:
                R = double_point(curve_coefficient, R, modulo, print_mode=False)
            else:
                R = summarize_points(R, point, modulo, print_mode=False)
            if print_mode: print(f"{f'•{R}' if R != "O" else f'{R}'}")
    # if R == point:
    #     R = double_point(curve_coefficient, R, modulo, print_mode=False)
    # else:
    #     R = summarize_points(R, point, modulo, print_mode=False)
    return R


def main() -> None:
    """
    Основная функция
    """
    a, _, mod, points = init_curve()
    p_point = choose_point(points, point_letter="P")
    k = int(input("\nВведите значение скаляра >> "))

    result = scalar_multiplexer(k, p_point, a, mod)
    print(f"\n{k}P = {f'•{result}' if result != "O" else f'{result}'}")


if __name__ == "__main__":
    main()

from lab4 import to_lower_index, init_curve, choose_point, summarize_points, double_point
from math import sqrt, ceil
from lab5 import scalar_multiplexer


def main() -> None:
    """
    Основная функция
    """
    a, _, mod, points = init_curve()
    p_point = choose_point(points, point_letter="P")
    N_1 = mod + 1 + 2 * sqrt(mod)
    m = ceil(sqrt(N_1))

    print(f"N{to_lower_index(1)} = {N_1}")
    print(f"m = {m}", end="\n\n")

    t_pairs = [(t, scalar_multiplexer(t, p_point, a, mod, print_mode=False)) for t in range(1, m + 1)]
    print(f"{'t'.ljust(5)}{'tP'.ljust(5)}")
    [print(f"{str(t_pair[0]).ljust(5)}{str(t_pair[-1]).ljust(5)}") for t_pair in t_pairs]

    Q = scalar_multiplexer(m, p_point, a, mod, print_mode=False)
    print(f"\nQ = -mP = -{Q} = ({Q[0]}, -{Q[-1]})", end=" = ")
    Q = (Q[0], -Q[-1] % mod)
    print(f"{Q} mod ({mod})")

    R = "O"
    print("R = O", end="\n\n")

    for i in range(m):
        for t_pair in t_pairs:
            t, tP = t_pair
            if R == tP:
                n = m * i + t
                print(f"i = {i}: R = •{R}")
                print(f"Точка найдена в таблице, поэтому порядок точки (P) n = m * i + t = {m} * {i} + {t} = {n}")
                break
        else:
            print(f"i = {i}: R = {f'•{R}' if R != "O" else f'{R}'} нет в таблице, "
                  f"поэтому R = {f'•{R}' if R != "O" else f'{R}'} + •{Q}", end=" = ")
            if R == Q:
                R = double_point(a, R, mod, print_mode=False)
            else:
                R = summarize_points(R, Q, mod, print_mode=False)
            print(f'•{R}' if R != "O" else f'{R}')
            continue

        break
    else:
        print("Точка так и не была найдена в таблице")


if __name__ == "__main__":
    main()

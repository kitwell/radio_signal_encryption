import gostcrypto
from GOST_3410_2018 import create_curve
from os import urandom

# 1. Вызов 34.10

gost34102018 = create_curve()

# 2. Генерация ключей

private_key = int.from_bytes(urandom(32), 'big') % gost34102018.q
while private_key == 0:
    private_key = int.from_bytes(urandom(32), 'big') % gost34102018.q

public_key = gost34102018.public_key(private_key)
print("Генерация ключей:")
print(f"Приватный ключ: {private_key:064x}")
print(f"Открытый ключ: \n   x = {public_key[0]:064x}, \n   y = {public_key[1]:064x}\n")

# 3. Хеширование

text = input("Введите текст сообщения:\n")
hash_text = gostcrypto.gosthash.new('streebog256', data = text.encode('cp1251'))
digest = hash_text.digest()

print(f"\nПолучение хеша сообщения:\n{hash_text.hexdigest()}\n")

# 4. Подпись

signature = gost34102018.sign(private_key, digest)

print("Получение подписи:\n")
print(f"Первая компонента - r: {signature[:32].hex()}")
print(f"Вторая компонента - s: {signature[32:].hex()}")
print(f"Полная подпись: {signature.hex()}\n")

# 4. Проверка подписи
is_valid = gost34102018.verify(public_key, digest, signature)
print(f"Проверка подписи\nПодпись верна: {is_valid}")

# # 5. Проверка с измененным хешем
# fake_digest = urandom(32)
# is_valid_fake = gost34102018.verify(public_key, fake_digest, signature)
# print(f"Подпись с фальшивым хешем: {is_valid_fake}")
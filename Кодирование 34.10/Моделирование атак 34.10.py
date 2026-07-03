"""
Консольное приложение для имитации системы криптографической защиты
дистанционного управления агропромышленной техникой на основе ГОСТ 34.10-2018.

В пакете передаются:
- ID отправителя и получателя (имена сущностей)
- Номер пакета (счётчик)
- Временная метка (наносекунды)
- Тело сообщения
- Электронная подпись
"""

import time
import gostcrypto
from GOST_3410_2018 import create_curve
from os import urandom
from dataclasses import dataclass
from typing import Any, Dict, Tuple, List


# =============================================================================
# Криптографический провайдер на основе ГОСТ 34.10-2018 и ГОСТ 34.11-2018
# =============================================================================

class GostProvider:
    """Провайдер криптографических операций на основе ГОСТ 34.10-2018"""
    
    def __init__(self):
        # Создаём кривую согласно ГОСТ 34.10-2018
        self.curve = create_curve()
        self._private_key = None
        self._public_key = None
    
    def get_algorithm_description(self) -> str:
        return "ГОСТ 34.10-2018 (эллиптическая кривая, 256 бит) + ГОСТ 34.11-2018 (Стрибог)"
    
    def generate_keypair(self):
        """Генерирует пару ключей согласно ГОСТ 34.10-2018"""
        # Генерация приватного ключа
        private_key = int.from_bytes(urandom(32), 'big') % self.curve.q
        while private_key == 0:
            private_key = int.from_bytes(urandom(32), 'big') % self.curve.q
        
        # Генерация публичного ключа
        public_key = self.curve.public_key(private_key)
        
        self._private_key = private_key
        self._public_key = public_key
        
        return KeyPair(private_key, public_key)
    
    def sign(self, private_key: int, data: bytes) -> bytes:
        """Подписывает данные с использованием ГОСТ 34.10-2018"""
        # Хешируем данные по ГОСТ 34.11-2018 (Стрибог 256)
        digest = self.hash(data)
        # Подписываем хеш
        signature = self.curve.sign(private_key, digest)
        return signature
    
    def verify(self, public_key: Tuple[int, int], data: bytes, signature: bytes) -> bool:
        """Проверяет подпись согласно ГОСТ 34.10-2018"""
        # Хешируем данные по ГОСТ 34.11-2018 (Стрибог 256)
        digest = self.hash(data)
        # Проверяем подпись
        return self.curve.verify(public_key, digest, signature)
    
    def hash(self, data: bytes) -> bytes:
        """Вычисляет хеш по ГОСТ 34.11-2018 (Стрибог 256)"""
        hash_obj = gostcrypto.gosthash.new('streebog256', data=data)
        return hash_obj.digest()
    
    def get_signature_components(self, signature: bytes) -> Tuple[str, str]:
        """Разбивает подпись на компоненты r и s"""
        if len(signature) == 64:
            r = signature[:32].hex()
            s = signature[32:].hex()
            return r, s
        else:
            return signature.hex(), ""
    
    def get_key_id(self, public_key: Tuple[int, int]) -> str:
        """Вычисляет идентификатор ключа по ГОСТ 34.11-2018 (Стрибог 256)"""
        # Сериализуем публичный ключ
        pub_bytes = str(public_key[0]).encode() + b',' + str(public_key[1]).encode()
        # Хешируем по ГОСТ 34.11-2018
        digest = self.hash(pub_bytes)
        # Берём первые 8 байт (16 hex символов) для краткости
        return digest[:8].hex()


# =============================================================================
# Вспомогательные структуры
# =============================================================================

@dataclass
class KeyPair:
    private: int
    public: Tuple[int, int]


# =============================================================================
# Константы протокола
# =============================================================================

PROTOCOL_VERSION = 1
MSG_TYPE_COMMAND = 0x01
MSG_TYPE_ACK = 0x02


# =============================================================================
# Сущность (оператор, машина) с расширенным выводом
# =============================================================================

class Entity:
    def __init__(self, name: str, provider: GostProvider):
        self.name = name
        self.provider = provider
        self.keypair = provider.generate_keypair()
        self.trusted_keys: Dict[str, Tuple[int, int]] = {}   # имя сущности -> открытый ключ
        self.last_timestamp: int = 0
        self.packet_counter: int = 0             # сквозной счётчик пакетов для этой сущности
        self._message_counter = 0                # для нумерации в выводе (не в пакете)

    def get_id(self) -> str:
        return self.name

    def get_public_key(self) -> Tuple[int, int]:
        return self.keypair.public

    def get_key_id(self) -> str:
        return self.provider.get_key_id(self.keypair.public)

    def get_key_display(self) -> str:
        return f"{self.name} (ID ключа: {self.get_key_id()})"

    def add_trusted(self, entity_id: str, public_key: Tuple[int, int]) -> None:
        self.trusted_keys[entity_id] = public_key

    def remove_trusted(self, entity_id: str) -> None:
        if entity_id in self.trusted_keys:
            del self.trusted_keys[entity_id]

    def get_trusted_list(self) -> List[str]:
        return list(self.trusted_keys.keys())

    def get_trusted_display_list(self) -> List[str]:
        result = []
        for name in self.trusted_keys:
            pub_key = self.trusted_keys[name]
            key_id = self.provider.get_key_id(pub_key)
            result.append(f"{name} ({key_id})")
        return result

    def _log(self, msg: str, indent: int = 2) -> None:
        print(" " * indent + msg)

    def _format_packet(self, msg: Dict[str, Any]) -> str:
        msg_type = "Команда" if msg['msg_type'] == MSG_TYPE_COMMAND else "Подтверждение"
        lines = []
        lines.append("  Пакет:")
        lines.append(f"    Заголовок: версия={PROTOCOL_VERSION}, тип={msg_type}")
        lines.append(f"    ID отправителя: {msg['sender']} ({len(msg['sender'])} байт)")
        lines.append(f"    ID получателя: {msg['receiver']} ({len(msg['receiver'])} байт)")
        lines.append(f"    Номер пакета: {msg['packet_number']} (4 байта)")
        lines.append(f"    Временная метка: {msg['timestamp']} (8 байт)")
        lines.append(f"    Тело сообщения: {msg['payload'].decode()} ({len(msg['payload'])} байт)")
        sig_len = len(msg['signature'])
        r, s = self.provider.get_signature_components(msg['signature'])
        if r and s:
            lines.append(f"    Электронная подпись: r={r[:16]}..., s={s[:16]}... ({sig_len} байт)")
        else:
            lines.append(f"    Электронная подпись: {msg['signature'].hex()[:32]}... ({sig_len} байт)")
        lines.append(f"    Итоговая длина пакета: {msg['packet_length']} байт")
        return "\n".join(lines)

    def create_signed_message(
        self,
        receiver_id: str,
        payload: bytes,
        timestamp: int,
        msg_type: int = MSG_TYPE_COMMAND
    ) -> Dict[str, Any]:
        self.packet_counter += 1
        self._message_counter += 1
        msg_num = self._message_counter
        packet_num = self.packet_counter

        print(f"\n  [Сообщение #{msg_num}] Формирование от {self.name} для {receiver_id}")
        self._log(f"Открытый ключ отправителя: {self.get_key_display()}")

        # Данные для подписи: receiver_id + packet_number + timestamp + payload
        data_to_sign = (
            receiver_id.encode() +
            str(packet_num).encode() +
            str(timestamp).encode() +
            payload
        )
        self._log(f"Данные для подписи (hex): {data_to_sign.hex()[:64]}... (длина {len(data_to_sign)} байт)")

        digest = self.provider.hash(data_to_sign)
        self._log(f"Хеш сообщения (ГОСТ 34.11 / Стрибог 256): {digest.hex()}")

        signature = self.provider.sign(self.keypair.private, data_to_sign)

        # Длина пакета: заголовок (4) + ID отправителя + ID получателя + номер пакета (4) + метка (8) + тело + подпись
        packet_length = 4 + len(self.name) + len(receiver_id) + 4 + 8 + len(payload) + len(signature)
        message = {
            'sender': self.name,
            'receiver': receiver_id,
            'packet_number': packet_num,
            'timestamp': timestamp,
            'payload': payload,
            'signature': signature,
            'msg_type': msg_type,
            'packet_length': packet_length,
            '_digest': digest,
            '_data_signed': data_to_sign
        }
        self._log("Сообщение подписано и готово к отправке.")
        print(self._format_packet(message))
        return message

    def verify_message(self, message: Dict[str, Any]) -> bool:
        print(f"\n  [Проверка] {self.name} проверяет сообщение от {message['sender']}")

        if message['receiver'] != self.name:
            self._log(f"ОШИБКА: адресат {message['receiver']} не совпадает с {self.name}")
            return False

        sender = message['sender']
        if sender not in self.trusted_keys:
            self._log(f"ОШИБКА: отправитель '{sender}' не доверен")
            return False

        sender_key = self.trusted_keys[sender]
        sender_key_id = self.provider.get_key_id(sender_key)
        self._log(f"Открытый ключ отправителя найден в списке доверенных: {sender} (ID ключа: {sender_key_id})")

        data_to_verify = (
            message['receiver'].encode() +
            str(message['packet_number']).encode() +
            str(message['timestamp']).encode() +
            message['payload']
        )
        self._log(f"Данные для проверки (hex): {data_to_verify.hex()[:64]}... (длина {len(data_to_verify)} байт)")

        digest_local = self.provider.hash(data_to_verify)
        self._log(f"Вычисленный хеш: {digest_local.hex()}")
        if '_digest' in message:
            self._log(f"Хеш отправителя:  {message['_digest'].hex()}")
            self._log(f"Совпадение хешей: {'ДА' if digest_local == message['_digest'] else 'НЕТ'}")

        is_valid = self.provider.verify(self.trusted_keys[sender], data_to_verify, message['signature'])
        self._log(f"Результат проверки подписи: {'УСПЕШНО' if is_valid else 'НЕДЕЙСТВИТЕЛЬНА'}")

        if not is_valid:
            self._log("Сообщение отклонено: подпись не совпадает (целостность нарушена или подделка)")
            return False

        # Защита от replay: проверяем временную метку (она должна быть больше последней)
        if message['timestamp'] <= self.last_timestamp:
            self._log(f"ОШИБКА: временная метка {message['timestamp']} не больше последней {self.last_timestamp}")
            self._log("Сообщение отклонено: replay-атака")
            return False

        self.last_timestamp = message['timestamp']
        self._log(f"Временная метка {message['timestamp']} обновлена, защита от повторов активна")
        self._log("Сообщение принято: подлинность, целостность и актуальность подтверждены")
        return True


# =============================================================================
# Вспомогательные функции для красивого вывода
# =============================================================================

def print_header(text: str) -> None:
    print("\n" + "=" * 80)
    print(f" {text}")
    print("=" * 80)


# =============================================================================
# Основная симуляция
# =============================================================================

def run_simulation(provider: GostProvider) -> None:
    print_header("ИМИТАЦИЯ ЗАЩИЩЁННОГО ОБМЕНА КОМАНДАМИ (ГОСТ 34.10-2018)")
    print(f"Криптографический провайдер: {provider.get_algorithm_description()}")

    operator = Entity("Operator", provider)
    operator2 = Entity("Operator2", provider)
    operator3 = Entity("Operator3", provider)
    machine = Entity("Machine", provider)

    print("\n--- Обмен открытыми ключами ---")
    machine.add_trusted(operator.get_id(), operator.get_public_key())
    machine.add_trusted(operator2.get_id(), operator2.get_public_key())
    machine.add_trusted(operator3.get_id(), operator3.get_public_key())
    operator.add_trusted(machine.get_id(), machine.get_public_key())
    operator2.add_trusted(machine.get_id(), machine.get_public_key())
    operator3.add_trusted(machine.get_id(), machine.get_public_key())

    print("Доверенные открытые ключи у Машины (ID -> ключ):")
    for entry in machine.get_trusted_display_list():
        print(f"  - {entry}")
    print("\nОператор доверяет Машине, Машина доверяет трём операторам.")

    # Сценарий 1
    print_header("Сценарий 1: Нормальная передача команды и подтверждения")
    timestamp = time.time_ns()  # наносекунды
    command = b"SPEED=10"
    print(f"\nКоманда: {command.decode()}, временная метка: {timestamp}")

    msg = operator.create_signed_message(machine.get_id(), command, timestamp, MSG_TYPE_COMMAND)
    print("\n--- Отправка команды на Машину ---")
    ok = machine.verify_message(msg)

    if ok:
        print("\nМашина приняла команду. Формирование подтверждения...")
        ack_timestamp = time.time_ns()
        ack_payload = b"ACK: command accepted"
        ack_msg = machine.create_signed_message(operator.get_id(), ack_payload, ack_timestamp, MSG_TYPE_ACK)
        print("\n--- Отправка подтверждения Оператору ---")
        ok2 = operator.verify_message(ack_msg)
        if ok2:
            print("\nОператор принял подтверждение. Обмен завершён успешно.")
        else:
            print("\nОШИБКА: подтверждение не прошло проверку.")
    else:
        print("\nОШИБКА: команда не прошла проверку.")

    # Сценарий 2
    print_header("Сценарий 2: Пассивный перехват (прослушивание)")
    timestamp2 = time.time_ns()
    command2 = b"SPEED=20"
    print(f"\nКоманда: {command2.decode()}, временная метка: {timestamp2}")
    msg2 = operator.create_signed_message(machine.get_id(), command2, timestamp2, MSG_TYPE_COMMAND)

    print("\n--- Злоумышленник перехватывает пакет ---")
    print("Перехваченный пакет:")
    print(operator._format_packet(msg2))
    print("Злоумышленник только прослушивает, данные не изменяются.")

    print("\n--- Машина получает оригинальное сообщение ---")
    ok3 = machine.verify_message(msg2)
    if ok3:
        print("\nМашина приняла команду (пассивный перехват не влияет на целостность).")
    else:
        print("\nНЕОЖИДАННАЯ ОШИБКА: сообщение отвергнуто.")

    # Сценарий 3
    print_header("Сценарий 3: Активная модификация (MITM)")
    timestamp3 = time.time_ns()
    command3 = b"SPEED=30"
    print(f"\nКоманда: {command3.decode()}, временная метка: {timestamp3}")
    msg3 = operator.create_signed_message(machine.get_id(), command3, timestamp3, MSG_TYPE_COMMAND)

    print("\n--- Злоумышленник перехватывает и изменяет payload ---")
    fake_msg = msg3.copy()
    fake_msg['payload'] = b"SPEED=100"
    print(f"  Изменённая нагрузка: {fake_msg['payload'].decode()}")
    print("  Оригинальная подпись оставлена без изменений.")
    print("Изменённый пакет:")
    print(operator._format_packet(fake_msg))

    print("\n--- Машина получает изменённое сообщение ---")
    ok4 = machine.verify_message(fake_msg)
    if ok4:
        print("\nОШИБКА: машина приняла поддельное сообщение (этого не должно быть).")
    else:
        print("\nМашина отвергла поддельное сообщение: целостность нарушена.")

    # Сценарий 4
    print_header("Сценарий 4: Replay-атака")
    timestamp4 = time.time_ns()
    command4 = b"TURN_LEFT"
    print(f"\nКоманда: {command4.decode()}, временная метка: {timestamp4}")
    msg4 = operator.create_signed_message(machine.get_id(), command4, timestamp4, MSG_TYPE_COMMAND)

    print("\n--- Легитимная отправка ---")
    ok5 = machine.verify_message(msg4)
    if ok5:
        print("\nМашина приняла команду.")
    else:
        print("\nОШИБКА: легитимная команда не прошла.")

    print("\n--- Злоумышленник повторяет тот же пакет (replay) ---")
    replay_msg = msg4.copy()
    print(f"  Повторная отправка с той же временной меткой {replay_msg['timestamp']}")

    print("\n--- Машина проверяет повторный пакет ---")
    ok6 = machine.verify_message(replay_msg)
    if ok6:
        print("\nОШИБКА: машина приняла повтор (защита от replay не сработала).")
    else:
        print("\nМашина отвергла повтор: временная метка не уникальна (replay-атака).")

    # Сценарий 5
    print_header("Сценарий 5: Инсайдер — отзыв ключа")
    print("\n--- Текущий список доверенных открытых ключей у Машины ---")
    for entry in machine.get_trusted_display_list():
        print(f"  - {entry}")

    print("\n--- Имитация увольнения оператора ---")
    print("Удаляем открытый ключ оператора из доверенных у Машины.")
    machine.remove_trusted(operator.get_id())

    print("\nОбновлённый список доверенных открытых ключей у Машины (после отзыва):")
    for entry in machine.get_trusted_display_list():
        print(f"  - {entry}")

    timestamp5 = time.time_ns()
    command5 = b"STOP"
    print(f"\nУволенный оператор пытается отправить команду: {command5.decode()}")
    msg5 = operator.create_signed_message(machine.get_id(), command5, timestamp5, MSG_TYPE_COMMAND)

    print("\n--- Машина проверяет сообщение от уволенного оператора ---")
    ok7 = machine.verify_message(msg5)
    if ok7:
        print("\nОШИБКА: машина приняла команду от уволенного оператора (ключ должен быть отозван).")
    else:
        print("\nМашина отвергла команду: отправитель не доверен (ключ отозван).")

    print("\n--- Восстановление доверия для завершения демонстрации ---")
    machine.add_trusted(operator.get_id(), operator.get_public_key())
    print("Ключ оператора снова доверен.")
    print("Текущий список доверенных у Машины:")
    for entry in machine.get_trusted_display_list():
        print(f"  - {entry}")

    print_header("СИМУЛЯЦИЯ ЗАВЕРШЕНА")
    print("Все сценарии выполнены. Вывод демонстрирует работу криптографической защиты.")


# =============================================================================
# Точка входа
# =============================================================================

def main() -> None:
    try:
        provider = GostProvider()
        print("Используется ГОСТ 34.10-2018 + ГОСТ 34.11-2018 (Стрибог 256)")
    except ImportError as e:
        print(f"Ошибка импорта: {e}")
        print("Убедитесь, что установлены библиотеки: gostcrypto, GOST_3410_2018")
        return

    run_simulation(provider)


if __name__ == "__main__":
    main()
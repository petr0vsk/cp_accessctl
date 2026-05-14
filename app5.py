import os
import json
import urllib3
import requests
from dotenv import load_dotenv

# Отключаем предупреждения о непроверенных HTTPS-запросах для чистоты вывода
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CheckPointClient:
    """Клиент для работы с Management API Check Point."""

    def __init__(self, host, port, username, password, verify=True):
        self.base_url = f"https://{host}:{port}/web_api"
        self.username = username
        self.password = password
        self.verify = verify
        self.sid = None

    def call(self, command, payload=None):
        """Выполняет POST-запрос к API и возвращает JSON-ответ."""
        url = f"{self.base_url}/{command}"
        headers = {"Content-Type": "application/json"}

        if self.sid:
            headers["X-chkp-sid"] = self.sid

        response = requests.post(
            url,
            json=payload or {},
            headers=headers,
            verify=self.verify,
            timeout=30,
        )

        try:
            data = response.json()
        except ValueError:
            raise RuntimeError(
                f"Non-JSON response from {command}: {response.text}"
            )

        if not response.ok:
            raise RuntimeError(f"API error in {command}: {data}")

        return data

    def login(self):
        """Авторизация на сервере и получение SID сессии."""
        data = self.call(
            "login",
            {
                "user": self.username,
                "password": self.password,
            },
        )
        self.sid = data["sid"]
        return data

    def logout(self):
        """Завершение сессии и очистка SID."""
        if self.sid:
            try:
                return self.call("logout")
            finally:
                self.sid = None

    @staticmethod
    def print_user_time_info(user_data):
        """Выводит данные о времени доступа из свойств объекта User."""
        user_name = user_data.get("name", "Unknown")
        connect_daily = user_data.get("connect-daily")
        from_hour = user_data.get("from-hour", "00:00")
        to_hour = user_data.get("to-hour", "23:59")
        connect_days = user_data.get("connect-on-days", [])

        print(f"\n{'=' * 15} Пользователь: {user_name} {'=' * 15}")
        print(f"Часы работы (User Profile): {from_hour} - {to_hour}")

        if connect_daily:
            print("Дни: Ежедневно")
        elif connect_days:
            print(f"Дни: {', '.join(connect_days)}")
        else:
            print("Дни: Не заданы (по умолчанию Any)")
        print(f"{'=' * 60}")

    def get_time_objects_from_role(self, role_name):
        """Находит имена объектов Time, привязанных к правилам с этой ролью."""
        print(f"\n[*] Поиск связанных объектов Time для роли: {role_name}...")
        time_names = set()

        try:
            # Ищем все места, где используется роль
            usage = self.call("where-used", {"name": role_name})
            used_directly = usage.get("used-directly", {})
            rules = used_directly.get("access-control-rules", [])

            for rule_entry in rules:
                rule_uid = rule_entry.get("rule", {}).get("uid")
                layer_uid = rule_entry.get("layer", {}).get("uid")

                # Запрашиваем детали конкретного правила
                rule_details = self.call("show-access-rule", {
                    "uid": rule_uid,
                    "layer": layer_uid
                })

                # Извлекаем объекты из колонки Time
                rule_times = rule_details.get("time", [])
                for t_obj in rule_times:
                    t_name = t_obj.get("name")
                    # Пропускаем "Any" (круглосуточно)
                    if t_name and t_name.lower() != "any":
                        time_names.add(t_name)

            return list(time_names)

        except Exception as e:
            print(f"[-] Ошибка при поиске объектов Time: {e}")
            return []

    def print_time_object_info(self, time_name):
        """Выгружает и расшифровывает настройки конкретного объекта Time."""
        try:
            data = self.call("show-time", {"name": time_name})

            print(f"\n{'>' * 5} Объект TIME: {time_name} {'<' * 5}")

            # 1. Период действия объекта
            start_date = data.get("start", {}).get("iso-8601", "С текущего момента")
            if data.get("end-never"):
                end_date = "Бессрочно"
            else:
                end_date = data.get("end", {}).get("iso-8601", "Не задано")

            print(f"Срок действия: {start_date} ---> {end_date}")

            # 2. Дни недели (Recurrence)
            recurrence = data.get("recurrence", {})
            pattern = recurrence.get("pattern", "Daily")
            weekdays = recurrence.get("weekdays", [])
            print(f"Повторение: {pattern}")
            if weekdays:
                print(f"Активные дни: {', '.join(weekdays)}")

            # 3. Диапазоны часов (Hours Ranges)
            ranges = data.get("hours-ranges", [])
            enabled_ranges = [r for r in ranges if r.get("enabled")]
            if enabled_ranges:
                print("Активные интервалы часов:")
                for r in enabled_ranges:
                    print(f"  - с {r.get('from')} до {r.get('to')}")
            else:
                print("Интервалы часов: Круглосуточно (или не заданы)")

            print("-" * 50)

        except Exception as e:
            print(f"[-] Не удалось получить данные Time '{time_name}': {e}")


def main():
    """Основная логика выполнения задачи."""
    load_dotenv()
    client = CheckPointClient(
        host=os.getenv("MGMT_IP"),
        port=os.getenv("MGMT_PORT"),
        username=os.getenv("MGMT_USER"),
        password=os.getenv("MGMT_PASS"),
        verify=False
    )

    client.login()

    try:
        target_role = "user_ar_ra-filkina"
        print(f"[*] Анализ доступа для роли: {target_role}")

        # --- ЧАСТЬ 1: ПРОВЕРКА ПОЛЬЗОВАТЕЛЕЙ (как в app4) ---
        role_data = client.call("show-access-role", {"name": target_role})
        for obj in role_data.get("users", []):
            # Если это группа, смотрим ее состав
            if obj.get("type") == "user-group":
                group = client.call("show-user-group", {"uid": obj.get("uid")})
                for member in group.get("members", []):
                    if member.get("type") == "user":
                        u_data = client.call("show-user", {"uid": member.get("uid")})
                        client.print_user_time_info(u_data)
            # Если пользователь привязан напрямую
            elif obj.get("type") == "user":
                u_data = client.call("show-user", {"uid": obj.get("uid")})
                client.print_user_time_info(u_data)

        # --- ЧАСТЬ 2: ПРОВЕРКА ОБЪЕКТОВ TIME (новая логика) ---
        found_times = client.get_time_objects_from_role(target_role)

        if found_times:
            print(f"\n[!] Найдено объектов Time в правилах: {len(found_times)}")
            for t_name in found_times:
                client.print_time_object_info(t_name)
        else:
            print("\n[-] Специфических объектов Time в правилах не обнаружено (Any).")

    except Exception as e:
        print(f"\n[Критическая ошибка] {e}")

    finally:
        client.logout()


if __name__ == "__main__":
    main()


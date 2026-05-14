import os
import json
import urllib3
import requests
from dotenv import load_dotenv

# Отключаем предупреждения о непроверенных HTTPS-запросах
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
        """Выполняет POST-запрос к API и возвращает ответ в JSON."""
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
        """Авторизация на сервере и сохранение SID сессии."""
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
        """Извлекает и выводит данные о времени из объекта пользователя."""
        user_name = user_data.get("name", "Unknown")
        
        connect_daily = user_data.get("connect-daily")
        from_hour = user_data.get("from-hour", "Не задано")
        to_hour = user_data.get("to-hour", "Не задано")
        connect_days = user_data.get("connect-on-days", [])

        print(f"\n{'=' * 16} Время доступа для: {user_name} {'=' * 16}")
        print(f"Время начала (from-hour): {from_hour}")
        print(f"Время окончания (to-hour): {to_hour}")
        
        if connect_daily:
            print("Разрешенные дни: Ежедневно (connect-daily: true)")
        elif connect_days:
            print(f"Разрешенные дни: {', '.join(connect_days)}")
        else:
            print("Разрешенные дни: Не заданы (возможно Any)")
        print(f"{'=' * 66}\n")


def main():
    """Основная логика скрипта по выгрузке времени доступа."""
    load_dotenv()
    
    mgmt_ip = os.getenv("MGMT_IP")
    mgmt_port = os.getenv("MGMT_PORT")
    username = os.getenv("MGMT_USER")
    password = os.getenv("MGMT_PASS")

    client = CheckPointClient(
        host=mgmt_ip,
        port=mgmt_port,
        username=username,
        password=password,
        verify=False,
    )

    client.login()

    try:
        target_role = "user_ar_ra-filkina"
        print(f"[*] Шаг 1: Получаем данные Access Role: {target_role}")
        role_data = client.call("show-access-role", {"name": target_role})
        
        users_in_role = role_data.get("users", [])
        
        if not users_in_role:
            print("[-] К данной роли не привязаны пользователи или группы.")
            return

        for role_obj in users_in_role:
            print(
                f"[*] В роли найден объект: {role_obj.get('name')} "
                f"(Тип: {role_obj.get('type')})"
            )

            if role_obj.get("type") == "user-group":
                print(f"[*] Шаг 2: Получаем состав группы {role_obj.get('name')}")
                group_data = client.call(
                    "show-user-group", {"uid": role_obj.get("uid")}
                )
                members = group_data.get("members", [])
                
                if not members:
                    print("[-] Группа пуста.")
                    continue
                
                for member in members:
                    if member.get("type") == "user":
                        print(
                            f"[*] Шаг 3: Выгружаем настройки пользователя "
                            f"{member.get('name')}"
                        )
                        user_data = client.call(
                            "show-user", {"uid": member.get("uid")}
                        )
                        # Вызов метода из экземпляра класса
                        client.print_user_time_info(user_data)

            elif role_obj.get("type") == "user":
                print(
                    f"[*] Шаг 2 (Альт): Выгружаем настройки пользователя "
                    f"{role_obj.get('name')}"
                )
                user_data = client.call(
                    "show-user", {"uid": role_obj.get("uid")}
                )
                client.print_user_time_info(user_data)

    except RuntimeError as e:
        print(f"\n[Ошибка API] {e}")
        
    finally:
        client.logout()


if __name__ == "__main__":
    main()


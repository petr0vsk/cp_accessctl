import os
import json
import urllib3
import requests
from dotenv import load_dotenv

# Отключаем предупреждения о непроверенных HTTPS-запросах (чтобы очистить вывод)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CheckPointClient:
    # ... (Оставьте ваш класс CheckPointClient без изменений) ...
    def __init__(self, host, port, username, password, verify=True):
        self.base_url = f"https://{host}:{port}/web_api"
        self.username = username
        self.password = password
        self.verify = verify
        self.sid = None

    def call(self, command, payload=None):
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
            raise RuntimeError(f"Non-JSON response from {command}: {response.text}")

        if not response.ok:
            raise RuntimeError(f"API error in {command}: {data}")

        return data

    def login(self):
        data = self.call("login", {
            "user": self.username,
            "password": self.password,
        })
        self.sid = data["sid"]
        return data

    def logout(self):
        if self.sid:
            try:
                return self.call("logout")
            finally:
                self.sid = None


# --------------------------------------------------------------
#   Основная логика
# --------------------------------------------------------------
def main():
    load_dotenv()
    mgmt_ip   = os.getenv("MGMT_IP")
    mgmt_port = os.getenv("MGMT_PORT")
    username  = os.getenv("MGMT_USER")
    password  = os.getenv("MGMT_PASS")

    client = CheckPointClient(
        host = mgmt_ip,
        port = mgmt_port,
        username = username,
        password = password,
        verify = False,  # лучше заменить на путь к CA-сертификату
    )

    client.login()

    try:
        # Указываем имя искомого пользователя
        target_role = "user_ar_ra-filkina"
        
        # Запрашиваем информацию о пользователе
        role_data = client.call("show-access-role", {"name": target_role})
        
        print(f"================ Данные Access Role: {target_role} ================")
        # Выводим ответ в красивом JSON-формате
        print(json.dumps(role_data, indent=2, ensure_ascii=False))
        print("====================================================================")

        
    except RuntimeError as e:
        print(f"\n[Ошибка] Не удалось получить данные пользователя: {e}")
        
    finally:
        # Гарантируем, что сессия будет закрыта даже в случае ошибки
        client.logout()

if __name__ == "__main__":
    main()


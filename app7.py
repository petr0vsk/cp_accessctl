import os
import csv
import json
import urllib3
import requests
from dotenv import load_dotenv

# Отключаем предупреждения о непроверенных HTTPS-запросах
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CheckPointClient:
    """Клиент для взаимодействия с Management API Check Point."""

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
                f"Ожидался JSON, но получено от {command}: {response.text}"
            )

        if not response.ok:
            raise RuntimeError(f"Ошибка API в команде {command}: {data}")

        return data

    def login(self):
        """Авторизация на сервере и получение SID."""
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
        """Завершение сессии."""
        if self.sid:
            try:
                return self.call("logout")
            finally:
                self.sid = None

    def get_all_vpn_roles(self, search_pattern="user_ar_ra-"):
        """Ищет все объекты Access Role по фильтру с поддержкой пагинации."""
        print(f"[*] Поиск Ролей доступа по маске '{search_pattern}'...")
        all_roles = []
        limit = 50
        offset = 0

        try:
            while True:
                response = self.call(
                    "show-objects",
                    {
                        "type": "access-role",
                        "filter": search_pattern,
                        "limit": limit,
                        "offset": offset,
                        "details-level": "standard",
                    },
                )
                objects_page = response.get("objects", [])
                all_roles.extend(objects_page)

                total_objects = response.get("total", 0)
                if len(all_roles) >= total_objects:
                    break
                offset += limit

            print(f"[+] Найдено ролей: {len(all_roles)}")
            return all_roles
        except Exception as e:
            print(f"[-] Ошибка при поиске ролей: {e}")
            return []

    def check_role_usage(self, role_name):
        """
        Проверяет активность роли в правилах и возвращает статус и объекты Time.
        """
        time_names = set()
        is_active = False

        try:
            usage = self.call("where-used", {"name": role_name})
            rules = usage.get("used-directly", {}).get("access-control-rules", [])

            if not rules:
                return False, []

            for rule_entry in rules:
                rule_uid = rule_entry.get("rule", {}).get("uid")
                layer_uid = rule_entry.get("layer", {}).get("uid")

                rule_details = self.call(
                    "show-access-rule",
                    {"uid": rule_uid, "layer": layer_uid},
                )

                if rule_details.get("enabled", True):
                    is_active = True
                    for t_obj in rule_details.get("time", []):
                        t_name = t_obj.get("name")
                        if t_name and t_name.lower() != "any":
                            time_names.add(t_name)

            return is_active, list(time_names)
        except Exception as e:
            print(f"[-] Ошибка проверки правила ({role_name}): {e}")
            return False, []

    def extract_time_objects_summary(self, time_names):
        """
        Выгружает детали по списку объектов Time и возвращает агрегированные строки 
        для CSV: (имена, даты_начала, даты_окончания).
        """
        if not time_names:
            return "Any", "Always", "Never"

        starts, ends = [], []
        for time_name in time_names:
            try:
                data = self.call("show-time", {"name": time_name})
                start_date = data.get("start", {}).get("iso-8601", "Always")
                end_date = "Never" if data.get("end-never") else data.get("end", {}).get("iso-8601", "Never")
                
                starts.append(start_date)
                ends.append(end_date)
            except:
                starts.append("Error")
                ends.append("Error")

        return ", ".join(time_names), ", ".join(starts), ", ".join(ends)

    @staticmethod
    def extract_user_profile(user_data):
        """Форматирует параметры времени конкретного пользователя для CSV."""
        user_name = user_data.get("name", "Unknown")
        connect_daily = user_data.get("connect-daily")
        from_hour = user_data.get("from-hour", "00:00")
        to_hour = user_data.get("to-hour", "23:59")
        connect_days = user_data.get("connect-on-days", [])

        if connect_daily:
            days_str = "Daily"
        elif connect_days:
            days_str = ",".join(connect_days)
        else:
            days_str = "Any"

        return user_name, days_str, from_hour, to_hour


def main():
    load_dotenv()
    client = CheckPointClient(
        host=os.getenv("MGMT_IP"),
        port=os.getenv("MGMT_PORT"),
        username=os.getenv("MGMT_USER"),
        password=os.getenv("MGMT_PASS"),
        verify=False,
    )

    csv_filename = "vpn_users_export.csv"
    csv_headers = [
        "access_role", "user_name", "user_group", "access_status",
        "profile_days", "profile_start_time", "profile_end_time",
        "rule_time_objects", "rule_valid_from", "rule_valid_to"
    ]
    dataset = []

    client.login()
    try:
        roles = client.get_all_vpn_roles("user_ar_ra-")
        if not roles:
            print("[-] Завершение: роли не найдены.")
            return

        for idx, role in enumerate(roles, 1):
            role_name = role.get("name")
            print(f"[{idx}/{len(roles)}] Обработка роли: {role_name}...")

            # Получаем статус правила и объекты Time
            is_active, time_objects = client.check_role_usage(role_name)
            status_str = "Active" if is_active else "Disabled"
            
            # Извлекаем агрегированные даты из объектов Time
            time_str, valid_from, valid_to = client.extract_time_objects_summary(time_objects)

            # Выгружаем состав самой роли (пользователей)
            role_data = client.call("show-access-role", {"name": role_name})
            
            for obj in role_data.get("users", []):
                # Если это группа, раскрываем её
                if obj.get("type") == "user-group":
                    group_name = obj.get("name")
                    group_data = client.call("show-user-group", {"uid": obj.get("uid")})
                    
                    for member in group_data.get("members", []):
                        if member.get("type") == "user":
                            u_data = client.call("show-user", {"uid": member.get("uid")})
                            u_name, p_days, p_start, p_end = client.extract_user_profile(u_data)
                            
                            # Добавляем строку в наш датасет
                            dataset.append({
                                "access_role": role_name,
                                "user_name": u_name,
                                "user_group": group_name,
                                "access_status": status_str,
                                "profile_days": p_days,
                                "profile_start_time": p_start,
                                "profile_end_time": p_end,
                                "rule_time_objects": time_str,
                                "rule_valid_from": valid_from,
                                "rule_valid_to": valid_to
                            })

                # Если это пользователь напрямую
                elif obj.get("type") == "user":
                    u_data = client.call("show-user", {"uid": obj.get("uid")})
                    u_name, p_days, p_start, p_end = client.extract_user_profile(u_data)
                    
                    dataset.append({
                        "access_role": role_name,
                        "user_name": u_name,
                        "user_group": "", # Нет группы
                        "access_status": status_str,
                        "profile_days": p_days,
                        "profile_start_time": p_start,
                        "profile_end_time": p_end,
                        "rule_time_objects": time_str,
                        "rule_valid_from": valid_from,
                        "rule_valid_to": valid_to
                    })

        # Сохранение в CSV
        print(f"\n[*] Выгрузка завершена. Запись {len(dataset)} строк в {csv_filename}...")
        with open(csv_filename, mode="w", newline="", encoding="utf-8-sig") as file:
            writer = csv.DictWriter(file, fieldnames=csv_headers, delimiter=";")
            writer.writeheader()
            writer.writerows(dataset)
            
        print("[+] Файл успешно сохранен!")

    except Exception as e:
        print(f"\n[Критическая ошибка] {e}")

    finally:
        client.logout()

if __name__ == "__main__":
    main()

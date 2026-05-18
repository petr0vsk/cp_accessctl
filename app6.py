import os
import json
import urllib3
import requests
from dotenv import load_dotenv

# Отключаем предупреждения о непроверенных HTTPS-запросах для чистоты вывода
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

        # Добавляем Session ID (токен) в заголовок, если мы уже авторизованы
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
        """Авторизация на сервере и получение SID (токена сессии)."""
        data = self.call(
            "login",
            {
                "user": self.username,
                "password": self.password,
            },
        )
        # Сохраняем выданный сервером токен для последующих запросов
        self.sid = data["sid"]
        return data

    def logout(self):
        """Завершение сессии и уничтожение токена на сервере."""
        if self.sid:
            try:
                return self.call("logout")
            finally:
                self.sid = None

    def get_all_vpn_roles(self, search_pattern="user_ar_ra-"):
        """
        Ищет все объекты Access Role по заданному паттерну имени.
        Автоматически обрабатывает пагинацию (листает страницы API).
        """
        print(f"\n[*] Поиск Ролей доступа по паттерну '{search_pattern}'...")
        all_roles = []
        limit = 50  # Количество объектов за один запрос (размер страницы)
        offset = 0  # Сдвиг для следующей страницы

        try:
            while True:
                # ИСПОЛЬЗУЕМ УНИВЕРСАЛЬНЫЙ МЕТОД show-objects
                response = self.call(
                    "show-objects",
                    {
                        "type": "access-role",  # Фильтр по типу объекта
                        "filter": search_pattern, # Поиск по тексту (названию)
                        "limit": limit,
                        "offset": offset,
                        "details-level": "standard",
                    },
                )

                # Получаем список ролей из текущей "страницы"
                objects_page = response.get("objects", [])
                all_roles.extend(objects_page)

                # Смотрим, сколько всего таких объектов в базе
                total_objects = response.get("total", 0)
                print(f"  [+] Загружено {len(all_roles)} из {total_objects}")

                # Если загрузили все объекты, прерываем цикл
                if len(all_roles) >= total_objects:
                    break

                # Иначе сдвигаем offset для запроса следующей порции
                offset += limit

            print(f"[*] Поиск завершен. Найдено ролей: {len(all_roles)}\n")
            return all_roles

        except Exception as e:
            print(f"[-] Ошибка при поиске ролей: {e}")
            return []

    def check_role_usage_and_time(self, role_name):
        """
        Ищет правила, в которых используется роль (where-used).
        Проверяет, включено ли правило (enabled), и собирает объекты Time.
        Возвращает кортеж: (is_active, time_names_list).
        """
        time_names = set()
        is_active = False

        try:
            # Шаг 1: Ищем все места, где используется роль
            usage = self.call("where-used", {"name": role_name})
            used_directly = usage.get("used-directly", {})
            rules = used_directly.get("access-control-rules", [])

            if not rules:
                # Если роль не привязана ни к одному правилу — она неактивна
                return False, []

            # Шаг 2: Перебираем найденные правила
            for rule_entry in rules:
                rule_uid = rule_entry.get("rule", {}).get("uid")
                layer_uid = rule_entry.get("layer", {}).get("uid")

                # Шаг 3: Запрашиваем детали конкретного правила
                rule_details = self.call(
                    "show-access-rule",
                    {"uid": rule_uid, "layer": layer_uid},
                )

                # ПРОВЕРКА НА АКТИВНОСТЬ:
                # Если хотя бы одно правило с этой ролью включено (не Disabled)
                if rule_details.get("enabled", True):
                    is_active = True

                    # Извлекаем объекты из колонки Time
                    rule_times = rule_details.get("time", [])
                    for t_obj in rule_times:
                        t_name = t_obj.get("name")
                        # Игнорируем стандартный "Any"
                        if t_name and t_name.lower() != "any":
                            time_names.add(t_name)

            return is_active, list(time_names)

        except Exception as e:
            print(f"[-] Ошибка при проверке правила для {role_name}: {e}")
            return False, []

    def print_time_object_info(self, time_name):
        """Выгружает и расшифровывает настройки конкретного объекта Time."""
        try:
            data = self.call("show-time", {"name": time_name})

            print(f"\n{'>' * 4} Объект TIME: {time_name} {'<' * 4}")

            # 1. Срок действия объекта
            start_date = data.get("start", {}).get("iso-8601", "Сек. момента")
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
            # Оставляем только те интервалы, у которых стоит галочка (enabled)
            enabled_ranges = [r for r in ranges if r.get("enabled")]
            
            if enabled_ranges:
                print("Активные интервалы часов:")
                for r in enabled_ranges:
                    print(f"  - с {r.get('from')} до {r.get('to')}")
            else:
                print("Интервалы часов: Круглосуточно (или не заданы)")
                
            print("-" * 45)

        except Exception as e:
            print(f"[-] Не удалось получить данные Time '{time_name}': {e}")

    @staticmethod
    def print_user_time_info(user_data):
        """Выводит данные о времени доступа из свойств объекта User."""
        user_name = user_data.get("name", "Unknown")
        
        connect_daily = user_data.get("connect-daily")
        from_hour = user_data.get("from-hour", "00:00")
        to_hour = user_data.get("to-hour", "23:59")
        connect_days = user_data.get("connect-on-days", [])

        print(f"    {'=' * 10} Профиль User: {user_name} {'=' * 10}")
        print(f"    Часы работы: {from_hour} - {to_hour}")

        if connect_daily:
            print("    Разрешенные дни: Ежедневно")
        elif connect_days:
            print(f"    Разрешенные дни: {', '.join(connect_days)}")
        else:
            print("    Разрешенные дни: Не заданы (Any)")
        print(f"    {'=' * 45}")


def main():
    """Основная логика выполнения задачи (Концепция 1 + Аудит активности)."""
    load_dotenv()
    client = CheckPointClient(
        host=os.getenv("MGMT_IP"),
        port=os.getenv("MGMT_PORT"),
        username=os.getenv("MGMT_USER"),
        password=os.getenv("MGMT_PASS"),
        verify=False,
    )

    client.login()

    try:
        # Шаг 1: Получаем список всех ролей по нужному паттерну
        roles = client.get_all_vpn_roles("user_ar_ra-")

        if not roles:
            print("[-] Подходящих объектов не найдено.")
            return

        # Шаг 2: Идем по каждой найденной роли
        for role in roles:
            role_name = role.get("name")
            print(f"{'#' * 60}")
            print(f"Анализ объекта: {role_name}")

            # Шаг 3: Проверяем, используется ли роль в АКТИВНОМ правиле
            is_active, time_objects = client.check_role_usage_and_time(role_name)

            if not is_active:
                print(f"[-] Пропуск: правило отключено [Disabled] или отсутствует.")
                continue

            print("[+] Правило активно. Выгружаем данные...")

            # Шаг 4: Смотрим, кто находится внутри этой Роли доступа
            role_data = client.call("show-access-role", {"name": role_name})
            
            for obj in role_data.get("users", []):
                # Если привязана группа, раскрываем её состав
                if obj.get("type") == "user-group":
                    group = client.call(
                        "show-user-group", {"uid": obj.get("uid")}
                    )
                    for member in group.get("members", []):
                        if member.get("type") == "user":
                            u_data = client.call(
                                "show-user", {"uid": member.get("uid")}
                            )
                            client.print_user_time_info(u_data)
                            
                # Если пользователь привязан напрямую, без группы
                elif obj.get("type") == "user":
                    u_data = client.call(
                        "show-user", {"uid": obj.get("uid")}
                    )
                    client.print_user_time_info(u_data)

            # Шаг 5: Если на само правило повешены объекты Time, разбираем их
            if time_objects:
                print(f"\n  [!] Найдено объектов Time в правиле: {len(time_objects)}")
                for t_name in time_objects:
                    client.print_time_object_info(t_name)

    except Exception as e:
        print(f"\n[Критическая ошибка] {e}")

    finally:
        # Гарантируем корректное закрытие сессии
        client.logout()


if __name__ == "__main__":
    main()

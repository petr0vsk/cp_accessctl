# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------
#   Библиотеки
# ----------------------------------------------------------------------
import os
import json
import urllib3
import requests
from dotenv import load_dotenv

def cp_webapi_call(ip_addr: str, port: str, command: str, payload: dict, sid: str = "") -> dict:
    """
    Универсальный POST‑запрос к Web API Management Server.
    """
    url = f"https://{ip_addr}:{port}/web_api/{command}"
    headers = {"Content-Type": "application/json"}
    if sid:
        headers["X-chkp-sid"] = sid

    resp = requests.post(
        url,
        data=json.dumps(payload),
        headers=headers,
        verify=False,                     # отключаем проверку сертификата
        timeout=30,
    )

    # Попытка вернуть JSON‑ответ, иначе исключение
    try:
        return resp.json()
    except ValueError:
        raise RuntimeError(f"Bad response from {url}: {resp.text}")
    
def login(ip: str, port: str, user: str, password: str) -> str:
    """
    Авторизация на Management Server. Возвращает SID.
    """
    payload = {"user": user, "password": password}
    result = cp_webapi_call(ip, port, "login", payload, "")
    if "sid" not in result:
        raise RuntimeError(f"Login failed: {result}")
    return result["sid"]

def logout(ip: str, port: str, sid: str) -> dict:
    """
    Завершение сессии.
    """
    return cp_webapi_call(ip, port, "logout", {}, sid)

# --------------------------------------------------------------
#   Основная логика
# --------------------------------------------------------------
def main():
     
    load_dotenv()
    mgmt_ip   = os.getenv("MGMT_IP")
    mgmt_port = os.getenv("MGMT_PORT")
    username  = os.getenv("MGMT_USER")
    password  = os.getenv("MGMT_PASS")
    # Проверяем, что всё задано в .env
    if not all([mgmt_ip,  mgmt_port, username, password]):
        raise RuntimeError("Не заданы обязательные переменные окружения: MGMT_IP, MGMT_USER, MGMT_PASS")
    
    # Авторизуемся
    sid = login(mgmt_ip, mgmt_port, username, password)
    print(f"================ Session ID: {sid} ====================")

    try:
        pass
    finally:
        # ---------- Завершение сессии ----------
        logout_res = logout(mgmt_ip, mgmt_port, sid)
        print("\nLogout result:", json.dumps(logout_res, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()

    

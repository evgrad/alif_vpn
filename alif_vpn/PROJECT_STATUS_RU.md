# Alif VPN — состояние проекта

## Что реализовано в Django

- JWT регистрация, вход, обновление и отзыв refresh-токена.
- Регистрация устройства и аутентификация по токену устройства.
- Профиль, список серверов, создание/просмотр/завершение VPN-сессий и heartbeat.
- Защищённый nonce для рекламного просмотра и проверка HMAC callback.
- API статуса подписки, покупки, восстановления и входящих уведомлений магазина.
- API check-in/acknowledgement VPN-агента, выпуск одноразового токена узла.
- Команда обслуживания истёкших сессий, подписок, рекламных nonce и недоступных узлов.

## Что добавлено для узлов

`vpn_agent/` содержит Linux-агент MVP для применения и отзыва WireGuard peers.
Он работает только с HTTPS API и не исполняет произвольные команды от сервера.
См. `vpn_agent/README.md`.

## Что ещё требует внешней настройки или разработки

- Развёртывание VPN-узла Linux, настройка WireGuard, firewall/NAT и домена/HTTPS.
- Проверка Xray/Reality: серверный адаптер агента пока отсутствует.
- App Store / Google Play: нужны аккаунты, ключи API и проверяющая интеграция;
  endpoints покупок сейчас закрываются с HTTP 503.
- Рекламная сеть: нужен конкретный провайдер и его формат подписи/callback;
  задайте `AD_CALLBACK_SECRET` только для подходящего HMAC-адаптера.
- Production-защита агента: сейчас статический токен в заголовках; для выпуска
  следует включить mTLS, HTTPS, ротацию секретов и мониторинг.

## Запуск backend в PowerShell

Из каталога Django-проекта:

```powershell
..\venv\Scripts\Activate.ps1
python manage.py migrate
python manage.py check
python manage.py runserver 127.0.0.1:8000
```

В отдельном окне для периодического обслуживания:

```powershell
..\venv\Scripts\Activate.ps1
python manage.py run_maintenance --loop --interval 30
```

## Локальные адреса

- Админка: `http://127.0.0.1:8000/admin/`
- API base: `http://127.0.0.1:8000/api/v1/`
- Список серверов: `http://127.0.0.1:8000/api/v1/servers/`
- Регистрация: `http://127.0.0.1:8000/api/v1/auth/register/`
- Вход: `http://127.0.0.1:8000/api/v1/auth/login/`
- Android Emulator API base: `http://10.0.2.2:8000/api/v1/`

Добавьте Server в админке и укажите endpoint, `supported_protocols=["wireguard"]`,
WireGuard public key, порт, address pool CIDR и DNS. Переведите status в `active`.
Для тестирования локально сначала подключите реальный Linux WireGuard-узел и
агент; одна только запись Server в админке не создаёт работающий VPN-туннель.

## API маршруты

| Метод | Путь | Назначение |
|---|---|---|
| POST | `/auth/register/` | Регистрация и выдача JWT |
| POST | `/auth/login/` | Вход и выдача JWT |
| POST | `/auth/token/refresh/` | Ротация access/refresh токена |
| POST | `/auth/logout/` | Отзыв refresh-токена |
| POST | `/devices/` | Регистрация устройства |
| GET, DELETE | `/me/` | Профиль, удаление аккаунта |
| GET | `/servers/` | Доступные VPN-серверы |
| POST, GET | `/sessions/` | Создание и список VPN-сессий |
| POST | `/sessions/{uuid}/heartbeat/` | Heartbeat сессии |
| DELETE | `/sessions/{uuid}/` | Завершение сессии |
| POST | `/ad-views/` | Запрос nonce для рекламы |
| POST | `/ad-views/{uuid}/verify/` | Верификация рекламного callback |
| GET | `/subscription/` | Статус подписки |
| POST | `/subscription/purchases/` | Проверка покупки (пока 503) |
| POST | `/subscription/restore/` | Восстановление покупки (пока 503) |
| POST | `/webhooks/store-notifications/` | Уведомления магазина (пока 503) |
| POST | `/agent/check-in/` | Статус узла и получение изменений |
| POST | `/agent/acknowledgements/` | Подтверждение применения |

Все пути таблицы добавляются к `http://127.0.0.1:8000/api/v1`.

# ldap-proxy

LDAP-прокси, прозрачно проксирующий запросы между SCIM-коннектором Yandex 360
(adscim) и Authentik LDAP Outpost. Единственная функциональная трансформация —
динамическое формирование атрибутов `givenName` и `sn` из `displayName` для
пользовательских записей.

```
adscim ──LDAP──▶ ldap-proxy ──LDAP──▶ Authentik LDAP Outpost
```

Зачем нужен: Authentik не отдаёт `givenName`/`sn` отдельно; SCIM-коннектор
Yandex 360 их требует. Прокси разбирает ФИО из `displayName` (или `name`/`cn`
как fallback) на лету.

## Поведение

- Все LDAP-операции, кроме `Search*`, проходят без изменений.
- Для каждого `SearchResultEntry` с `objectClass` ∈ {`person`, `inetOrgPerson`,
  `organizationalPerson`, `user`} прокси:
  1. Берёт первое непустое значение из `displayName` → `name` → `cn`.
  2. Делит по первому пробелу: левая часть → `givenName`, правая → `sn`.
  3. Перезаписывает (или добавляет) `givenName`/`sn` в записи.
- Если в `Search`-запросе указан явный список атрибутов с `givenName`/`sn`,
  но без `displayName`/`name`/`cn` — прокси добавляет их в upstream-запрос и
  вычищает из ответа клиенту.
- Записи групп и любые non-user объекты проходят без модификаций.

## Переменные окружения

| Переменная                  | Назначение                                              | По умолчанию   |
|-----------------------------|---------------------------------------------------------|----------------|
| `PROXY_LISTEN`              | Адрес и порт прослушивания                              | `0.0.0.0:3389` |
| `UPSTREAM_ADDR`             | Адрес upstream LDAP                                     | `1.2.3.4:389`  |
| `UPSTREAM_TLS`              | Использовать LDAPS к upstream (`true`/`false`)          | `false`        |
| `UPSTREAM_TLS_SKIP_VERIFY`  | Пропустить проверку TLS-сертификата upstream            | `false`        |
| `LOG_LEVEL`                 | `debug` / `info` / `warn` / `error`                     | `info`         |
| `LOG_FORMAT`                | `text` / `json`                                         | `text`         |

## Локальный запуск

Из исходников:

```sh
go run ./cmd/ldap-proxy
```

Сборка бинарника:

```sh
go build -o ldap-proxy ./cmd/ldap-proxy
./ldap-proxy
```

Через Docker:

```sh
docker build -t ldap-proxy .
docker run --rm -p 3389:3389 \
    -e UPSTREAM_ADDR=1.2.3.4:389 \
    -e LOG_LEVEL=debug \
    ldap-proxy
```

Через docker-compose:

```sh
docker compose up --build
```

## Интеграция с adscim

В конфиге adscim замените URL upstream-LDAP на адрес прокси:

```yaml
ldap:
  urls:
    - ldap://ldap-proxy:3389
```

(в `docker-compose.yml` это раскомментированная секция `adscim`).

## Проверка через ldapsearch

```sh
ldapsearch -x -H ldap://localhost:3389 \
    -D "cn=service-account,ou=users,dc=example,dc=org" -w 'PASS' \
    -b "dc=example,dc=org" \
    "(objectClass=person)" \
    displayName givenName sn cn mail
```

В выводе для каждого пользователя должны быть `givenName` и `sn`, разобранные
из `displayName`.

## Тестирование

```sh
go test ./...
```

## Структура проекта

```
ldap-proxy/
├── cmd/ldap-proxy/main.go       — точка входа, конфиг, signal handling
├── internal/config/config.go    — загрузка конфигурации из ENV
├── internal/proxy/
│   ├── server.go                — TCP listener, lifecycle, graceful shutdown
│   ├── session.go               — клиент↔upstream pump, две горутины на сессию
│   ├── transform.go             — SplitFullName и BER-трансформация записей
│   ├── ldap.go                  — константы LDAP-тегов и BER-хелперы
│   └── transform_test.go        — unit-тесты разбора и трансформации
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Что вне области задачи

Кеширование, HA, метрики Prometheus, поддержка операций записи, SASL,
TLS на клиентской стороне прокси, Web UI.

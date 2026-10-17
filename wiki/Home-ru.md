# Keystone

*Раньше назывался **SPA (Single Point of Authorization, единая точка авторизации)**. Keystone — вход и доступ для
семейства Umbrella.*

[English version](Home.md)

Keystone — единственное место, где люди семейства Umbrella входят в систему и где решается их доступ. В Keystone хранятся
учётные записи, группы, парольная политика, ключи доступа (passkeys), подключения к каталогам (LDAP / Active
Directory, Microsoft Entra ID) и к внешним провайдерам входа (Google, Apple, любой провайдер OpenID Connect), и Keystone
решает, какие роли есть у человека в каждом приложении.

**Beacon, Current, Ledger, Network Control** и любые другие приложения OpenID Connect не
хранят ни паролей, ни парольной политики, ни ключей доступа, ни настроек каталогов: они отправляют людей входить в
Keystone, читают своих пользователей и их роли через API федерации Keystone, публикуют в Keystone свой каталог ролей и применяют
роли, которые выдаёт Keystone.

![Вход](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/signin-light.png)

- [docs/protocol.md](protocol.md) — как приложения подключаются к Keystone (OpenID Connect, ключ подключения, API
  федерации, синхронизация пользователей).
- [docs/api.md](api.md) — HTTP API: провайдер OpenID Connect, API федерации и API `/api/v1` веб-приложения.
- [docs/processes.md](processes.md) — бизнес-процессы внутри Keystone (на английском); между приложениями
  семейства: [family.md](https://onedev.evcsbrw.ru/Monitoring/Current/~files/main/docs/family.md).

Другие приложения семейства: [Beacon](https://onedev.evcsbrw.ru/Monitoring/Beacon) (оповещения систем мониторинга превращаются
в инциденты, вызовы дежурных и реагирование; раньше Umbrella Monitoring), [Ledger](https://onedev.evcsbrw.ru/Monitoring/Ledger)
(инвентарь — DCIM/IPAM — и табличные базы данных; раньше Inventory DB), [Current](https://onedev.evcsbrw.ru/Monitoring/Current)
(сетевой трафик и сетевые устройства; раньше Umbrella Flow) и Network Control.

## Возможности

| | |
| --- | --- |
| Вход | локальные пароли по парольной политике, LDAP / Active Directory, ключи доступа (Windows Hello, Touch ID, Face ID, Android, ключи безопасности), Microsoft Entra ID, Google, Apple, любой провайдер OpenID Connect |
| Люди и группы | локальные учётные записи и учётные записи из каталогов и от провайдеров; группы Keystone и группы каталогов (по DN или ID объекта Entra, их можно создать до первого входа участников) |
| Приложения | мастер из трёх шагов подключает приложение и один раз показывает ключ подключения; правила *человек или группа → роль* решают, кто и с какими ролями входит в какое приложение |
| Двухэтапная проверка | приложение-аутентификатор (TOTP, RFC 6238) как второй фактор после пароля (локального или каталога), одноразовые коды восстановления; парольная политика может требовать её от администраторов или от всех; ключ доступа сам по себе считается двумя факторами |
| Парольная политика | длина, цифры, специальные символы, регистр, разрешённые алфавиты, запрет распространённых паролей, срок действия с предупреждением, история, блокировка, обязательный второй фактор |
| Самообслуживание | смена пароля (в том числе истёкшего — прямо при входе), настройка двухэтапной проверки, добавление, переименование и удаление ключей доступа, просмотр и завершение сеансов |
| Аудит | каждый вход и каждое изменение, с поиском |
| Интерфейс | английский и русский языки, светлая и тёмная тема, дизайн Umbrella |

## Экраны

**Главная** — приложения человека и первые шаги для администраторов.

![Главная на русском](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/home-ru.png)
![Главная, тёмная тема](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/home-dark.png)

**Приложения** — подключение в три шага: приложение, кто какую роль получает, ключ подключения.

![Приложения](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/applications-light.png)
![Подключение: приложение](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/wizard-1-application.png)
![Подключение: доступ](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/wizard-2-access.png)
![Подключение: ключ](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/wizard-3-key.png)
![Приложения, тёмная тема](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/applications-dark.png)

**Пользователи и группы**

![Пользователи](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/users-light.png)
![Пользователи, тёмная тема](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/users-dark.png)
![Группы](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/groups.png)
![Группа каталога по DN](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/groups-directory.png)

**Настройки** — парольная политика, каталоги, провайдеры входа, общие настройки и ключ подписи.

![Парольная политика](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/password-policy.png)
![Каталоги](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/directories.png)
![Провайдеры входа](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/providers.png)
![Общие](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/general.png)
![Журнал аудита](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/audit.png)

**Профиль и безопасность** — пароль, двухэтапная проверка, ключи доступа и сеансы вошедшего человека.

![Профиль](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/profile-light.png)
![Профиль, тёмная тема](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/profile-dark.png)
![Настройка двухэтапной проверки](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/profile-totp-setup.png)

**Вход** — тёмная тема и смена пароля при первом входе.

![Вход, тёмная тема](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/signin-dark.png)
![Смена пароля](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/signin-change-password.png)
![Код приложения-аутентификатора](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/signin-totp.png)
![Двухэтапная проверка, которую требует политика, настраивается прямо при входе](https://onedev.evcsbrw.ru/Monitoring/Keystone/~raw?revision=main&file=docs/screens/signin-totp-setup-ru.png)

На снимках интерфейс на английском, кроме первого снимка главной страницы; язык переключается на странице входа
(EN / RU) и в меню пользователя.

## Запуск

### Docker Compose

```sh
./install.sh
```

`install.sh` создаёт `.env` со случайным `POSTGRES_PASSWORD` и ключ распечатывания OpenBao
(`openbao/keys/unseal.key`), запускает PostgreSQL, OpenBao и Keystone и печатает адрес, пароль PostgreSQL и команду,
которая показывает код установки. Откройте адрес в браузере — **мастер первичной настройки** проведёт по шагам:

1. **код установки** — одноразовый код из 12 символов, который Keystone пишет в журнал (`docker compose logs keystone |
   grep setup_code`) и в файл `/data/setup-code`; без него мастер ничего не принимает, после десяти неверных попыток
   код заменяется новым;
2. **хранилища** — PostgreSQL (по умолчанию сервис из compose-файла или свой) и OpenBao: встроенный, который мастер
   инициализирует сам (KV v2, AppRole для Keystone; root-токен и ключ восстановления показываются один раз и не
   хранятся — сохраните их), или внешний с AppRole (`role_id`, `secret_id`). Кнопка **«Проверить»** у каждого;
3. **первый администратор**, 4. **организация и публичный адрес**, 5. **доверенные прокси**.

После шага хранилищ Keystone переходит в обычный режим без перезапуска. Список **«Первые шаги»** на главной ведёт
дальше: парольная политика, ключ доступа, каталог, первое приложение и его роли.

Образ (`Dockerfile`) собирает веб-приложение на Node, сервер на Go и кладёт оба на distroless-основу (без root,
около 27 МБ). В продуктиве ставьте Keystone за TLS-прокси и добавьте прокси в мастере или в **«Настройки → Общие»**.

### Где что хранится

- **`.env`**: только `POSTGRES_PASSWORD` (для PostgreSQL из compose-файла; Keystone его не читает — мастер спрашивает
  его один раз) и при желании `SPA_PORT`.
- **`/data/bootstrap.json`** (том `keystone-data`, 0600): адрес PostgreSQL без пароля, адрес OpenBao и `role_id`
  AppRole; `/data/approle/secret_id` (0600) — единственный секрет на диске.
- **OpenBao** (KV v2): все пароли и секреты — хеши паролей и их история (`users/<id>/password`), приложения-
  аутентификаторы и коды восстановления (`users/<id>/totp`), хеши секретов клиентов и токенов федерации
  (`apps/<id>/credentials`, `apptokens/<hash>`), ключи подписи, секреты каталогов и провайдеров, пароль PostgreSQL
  (`infra/postgres`).
- **PostgreSQL**: несекретное — люди, группы, роли и правила, приложения, открытые ключи passkeys, сессии и
  одноразовые коды только хешами, настройки, журнал аудита.
- **«Настройки → Общие»**: публичный адрес (издатель), доверенные прокси, срок сессии.

Сам процесс читает только `SPA_DATA_DIR` (по умолчанию `/data`), `SPA_LISTEN` (по умолчанию `:8080`) и `SPA_WEB_DIR`.

### Обновление установки, сделанной до мастера

Установка, настроенная переменными `SPA_*` / `BAO_*`, продолжает работать: пока нет `bootstrap.json`, Keystone один
раз забирает их и пишет об этом в журнал.

- Если заданы `SPA_DATABASE_URL` и `BAO_ADDR` + `BAO_TOKEN`, он сам пишет `bootstrap.json` и запускается как раньше.
- Если секреты были зашифрованы `SPA_MASTER_KEY` в базе, мастер просит код и OpenBao (форма PostgreSQL заполнена из
  старых настроек, пароль оставьте пустым). Затем Keystone переносит зашифрованные секреты, хеши паролей, коды
  восстановления и учётные данные приложений в OpenBao и удаляет их из базы; ключ подписи, а значит издатель и токены
  приложений, остаётся прежним. Если в базе уже есть люди, остальные шаги пропускаются.
- `SPA_PUBLIC_URL`, `SPA_TRUSTED_PROXIES` и `SPA_SESSION_HOURS` переходят в **«Настройки → Общие»**.

Перед обновлением: сделайте резервную копию базы и `.env`, проверьте, что в `.env` есть `POSTGRES_PASSWORD`, с которым
создавалась база (старый compose-файл без него использовал `spa`), и запустите `./install.sh` (он сохраняет `.env`).
После обновления удалите строки `SPA_*` и `BAO_*` из `.env`.

### Двухэтапная проверка

Те, кто входит по паролю, — локальные учётные записи и учётные записи LDAP / Active Directory — включают
двухэтапную проверку в разделе **Профиль и безопасность**: отсканируйте QR-код приложением-аутентификатором (Google
Authenticator, Microsoft Authenticator, 1Password, Aegis и др.; или введите ключ), подтвердите кодом и сохраните
десять одноразовых кодов восстановления, которые показываются один раз. После этого Keystone после верного пароля
спрашивает 6-значный код (шаг 30 секунд, допускается расхождение часов на один шаг в каждую сторону, каждый код
принимается один раз); код восстановления один раз заменяет код из приложения. Отключение, смена приложения и
новые коды восстановления требуют текущего кода.

**Парольная политика → Второй фактор** делает её *обязательной для администраторов* или *обязательной для всех*:
тот, у кого она обязательна, но не настроена, настраивает её сразу после пароля, до завершения входа (в том числе
после смены истёкшего пароля). Вход с ключом доступа сам по себе двухфакторный и кода не спрашивает; при входе через
Microsoft Entra ID, Google, Apple или OpenID Connect второй фактор остаётся за провайдером. Администратор отключает
второй фактор человеку, потерявшему телефон (**Пользователи → Действия**).

Секрет хранится так же, как другие секреты Keystone, — в OpenBao или зашифрованным мастер-ключом в базе
(`totp/<id пользователя>`), а коды восстановления — только в виде ключевых хешей (HMAC-SHA256). Неверные коды
считаются как неверные пароли (блокировка по политике и 20 попыток с одного адреса за 5 минут). Настройка,
отключение, неверные коды и использованные коды восстановления пишутся в журнал аудита. Приложения видят вход по
паролю с кодом как `amr: ["pwd", "otp", "mfa"]`.

### Подключение приложения

**Приложения → Подключить приложение**: выберите тип, укажите адрес, выдайте группам или людям роли и скопируйте
**ключ подключения** (`spa1.…`) в переменную `SPA_CONNECTION_KEY` приложения. После этого приложение предлагает
«Войти через Keystone» и каждые 5 минут синхронизирует своих пользователей. **Выпустить новый ключ** заменяет ключ;
старый сразу перестаёт работать. Подробности: [docs/protocol.md](protocol.md).

## Разработка

```
backend/   сервер на Go: cmd/keystone, internal/app (HTTP), store (PostgreSQL), policy, totp, passkey, directory, entra, oidcx, secrets
web/       веб-приложение на React + TypeScript + Vite (src/pages, src/components, src/i18n)
scripts/   seed-demo.mjs (демо-данные через API), screenshots.mjs (снимки для README через Playwright),
           e2e-beacon.mjs (сквозная проверка с Beacon)
docs/      protocol.md, api.md, e2e.md, screens/
```

| | |
| --- | --- |
| `make build` | веб-приложение (`web/dist`) и сервер (`backend/keystone`) |
| `make test` | `go vet` и `go test ./...` (для тестов с базой задайте `SPA_TEST_POSTGRES`) и тесты веб-приложения (vitest) |
| `make run` | собрать и запустить Keystone с собранным веб-приложением (при первом запуске показывает мастер настройки; данные в `./data`) |
| `make dev` | веб-приложение с горячей перезагрузкой на `:5173`, API проксируется в Keystone на `:8080` |
| `make docker`, `make up`, `make down` | образ; Keystone и PostgreSQL в Docker Compose |
| `make seed` | демо-данные в запущенном Keystone: люди, группы, четыре приложения Umbrella, парольная политика |
| `make screenshots` | снимки в `docs/screens` (на пустой базе; Playwright с Chromium) |
| `make e2e-beacon` | сквозная проверка запущенного Keystone с настоящим Beacon в Chromium: подключение, роли, вход со вторым фактором, синхронизация, отключение ([docs/e2e.md](e2e.md)) |

Веб-приложение следует дизайну Umbrella (токены и элементы управления приложения Beacon, как в
Ledger): оболочка с боковым меню и блоком страницы, карточки, таблицы, «пилюли», сегментированные
переключатели и диалоги, светлая и тёмная темы (выбор хранится в `localStorage`, `spa.theme`), английский и русский
языки. Английские строки — ключи словарей `web/src/i18n/en.ts` и `ru.ts`; тест
`web/src/i18n/completeness.test.ts` падает, если для строки приложения или сообщения об ошибке API нет текста на
одном из языков.

Веб-приложение обращается только к API `/api/v1` с cookie сеанса; каждый изменяющий запрос несёт заголовок
`X-Requested-With: spa`. Аудиторы видят страницы администрирования только для чтения; роли проверяет API.

## Совместимость после переименования

Keystone раньше назывался SPA. Новое имя носят продукт, исполняемый файл (`cmd/keystone`, `/app/keystone` в образе),
образ Docker (`keystone`), проект и сервис compose (`keystone`), модуль Go (`github.com/sbrw-evc/keystone`) и пакет
веб-приложения (`@keystone/web`). Следующие идентификаторы намеренно сохраняют прежнее написание — от них зависят
подключённые приложения и существующие установки:

| сохранено | почему |
| --- | --- |
| протокол Keystone: префикс ключа `spa1.`, `SPA_CONNECTION_KEY`, `SPA_CONNECTION_KEY_FILE`, `SPA_PUBLIC_URL` в приложениях, `/api/spa/v1/*`, `/api/auth/spa/start` и `/api/auth/spa/callback` в приложениях, ключ OpenBao `spa/connection_key`, утверждение `spa_admin`, `source = spa` в приложениях | формат обмена между Keystone и каждым подключённым приложением ([docs/protocol.md](protocol.md)) |
| переменные окружения `SPA_*` (`SPA_DATABASE_URL`, `SPA_MASTER_KEY`, `SPA_TEST_POSTGRES`, …), `BAO_*` | существующие развёртывания |
| имя базы данных и пользователя `spa`, том compose `spa_pgdata`, имена таблиц и столбцов (`users.spa_role`) | существующие данные |
| точка монтирования OpenBao `spa` (значение `BAO_MOUNT` по умолчанию) | существующие секреты |
| cookie `spa_session`, `spa_sso`; идентификаторы клиентов `spa_…`, токены федерации `spat_…` | сеансы и выданные учётные данные остаются действительными |
| значение заголовка CSRF `X-Requested-With: spa`, поле JSON `spa_role` | клиенты API и скрипты |
| субъект `spa` в журнале аудита для действий самого Keystone | поиск по существующему журналу |
| ключи `localStorage` `spa.theme`, `spa.sidebar.collapsed`, `umbrella.locale` | сохранённые настройки людей |
| идентификаторы типов приложений `umbrella-monitoring`, `inventory-db`, `umbrella-flow` | по-прежнему принимаются API и превращаются в `beacon`, `ledger`, `current` (миграция `0004_app_types.sql` переписала сохранённые) |
| `make e2e-monitoring`, `UMBRELLA_MONITORING_DIR`, `UMBRELLA_MONITORING_REF` | синонимы `make e2e-beacon`, `BEACON_DIR`, `BEACON_REF` |

Репозиторий GitHub будет переименован в `sbrw-evc/keystone`; GitHub перенаправляет старый адрес.

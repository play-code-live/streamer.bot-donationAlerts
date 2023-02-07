# DonationAlerts для Streamer.bot

Данный модуль является набором действий и комманд для интеграции с DonationAlerts.

## Установка

> **Важно!** Если у вас уже есть подключенная интеграция более старой версии, воспользуйтесь инструкцией по обновлению

1. Загрузите свежую версию файла импорта **install.sb** со [страницы релизов](https://github.com/play-code-live/streamer.bot-donationAlerts/releases)
2. Откройте Streamer.bot и нажмите кнопку Import
3. Перетащите курсором мыши загруженный файл **install.sb** в область **Import String**, или скопируйте его содержимое и вставьте вручную
4. Нажмите кнопку Import
5. Перейдите на вкладку **Commands** и поставьте галочку **Enabled** у команд `!da_connect` и `!da_start`
6. Перейдите в чат вашего канала и введите команду `!da_connect`. В браузере откроется страница для авторизации в DonationAlerts, после чего интеграция запуститься и подключится в автозагрузку

## Обновление

1. На вкладке **Actions** удалите действие `-- DonationAlerts Code`
1. Загрузите свежую версию файла импорта **update.sb** со [страницы релизов](https://github.com/play-code-live/streamer.bot-donationAlerts/releases)
2. Откройте Streamer.bot и нажмите кнопку Import
3. Перетащите курсором мыши загруженный файл **update.sb** в область **Import String**, или скопируйте его содержимое и вставьте вручную
4. Нажмите кнопку Import
6. Перейдите в чат вашего канала и введите команду `!da_start`.

## Структура

Весь список команд можно поделить на две условные группы:

### Служебные действия

Все служебные действия размещены в группе **DonationAlerts** и имеют префикс `--DonationAlerts`. Все они плотно связаны друг с другом и не могут быть переименованны без нарушения работоспособности.

> **Важно!** Не переименовывайте служебные действия! Они имеют высокую зависимость друг от друга

* `--DonationAlerts Code` - Содержит основной код интеграции, который вызывается посредством **Call C# Method** в Streamer.bot
* `--DonationAlerts Authorization` - Основная логика авторизации в сервисе. Вызывается вводом команды `!da_connect`
* `--DonationAlerts Get Socket Token` - Логика получения ключей доступа для сокета. Вызывается автоматически после авторизации. Так же получает ключ обновления токена, что позволяет не выполнять повторый вход в сервис
* `--DonationAlerts Background Watcher` - Фоновое действие, отслеживающее появление новых донатов. Всегда должно находиться в очереди. Для ручной постановки в очередь, введите команду `!da_start`
* `--DonationAlerts Autostart` - Обеспечивает автоматический запуск фоновой задачи

### Действия-обработчики

Действия обработчики редактируются пользователем, для достижения желаемого эффекта реакции на донат. Однако, они имеют строго заданный шаблон именования.

Вся основная обработка донатов выполняется в действии `DonationHandler_Default`. Из него вы можете развести логику в зависимости от диапазонов сумм. Однако, для точной суммы, есть другой подход...

Если вы хотите обработать донат на конкретную сумму, вам необходимо создать действие `DonationHandler_SUM`, где вместо `SUM` вы указываете желаемое число.

## Аргументы

Каждое обработанное событие доната сопровождается следующими аргументами:

| Аргумент             | Описание                                                                                               |
| -------------------- | ------------------------------------------------------------------------------------------------------ |
| `daUsername`         | Имя пользователя. Не может быть пустым. В случаях анонимной поддержки подставляется значение Anonymous |
| `daMessage`          | Сообщение доната. Может быть пустым                                                                    |
| `daAmount`           | Сумма поддержки в валюте зрителя                                                                       |
| `daCurrency`         | Выбранная для поддержки валюта                                                                         |
| `daAmountConverteed` | Сумма поддержки в валюте аккаунта стримера                                                             |

## Автор

**play_code** <info@play-code.info>

https://twitch.tv/play_code
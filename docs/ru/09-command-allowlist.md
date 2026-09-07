# 9. Белый список команд и журнал

Этот инструмент запускают на продакшн-хостах люди, которые его не писали, и часто
от root. «Он только читает» легко сказать и невозможно проверить, читая обещание.
Чтобы это не приходилось принимать на веру, существуют два механизма: бинарь
способен выполнить ровно один опубликованный список команд, и он прикладывает к
отчёту запись того, что реально выполнил.

## Белый список

`app/run/commands.go` — это список. `app/run/allowlist.go` — его применение.
Устройство сознательно ограничительное, а не просто «по договорённости»:

- **Команду, которой нет в списке, выполнить нельзя.** Не «не следует»:
  `run.Runner` её отклоняет, а отказ попадает в журнал и, значит, в отчёт, а не в
  лог, который никто не сохранил.
- **Проверка происходит до поиска бинаря.** Существует ли команда на этом хосте —
  не наше дело, пока не установлено, что запускать её разрешено.
- **Аргументы сопоставляются тоже, не только имя бинаря.** Разрешение запускать
  `apt-get` — не то же самое, что разрешение устанавливать пакеты.
- **Ничто не идёт через шелл.** Команды запускаются через `exec` с вектором
  аргументов. Никакого `sh -c` в этом инструменте нет.
- **`--commands` печатает сам применяемый список**, а не его описание, поэтому то,
  что инструмент о себе говорит, и то, что он реально может запустить, разойтись не
  могут: у обоих один источник.

Добавить команду можно только правкой `app/run/commands.go` — поэтому она
появляется в ревью и в `--commands` в один и тот же момент.

### Какими могут быть аргументы

Большинство записей — фиксированные векторы аргументов, сопоставляемые буквально.
Там, где значение подставляется во время работы, оно записано как `<kind>` (или
`<kind>...` для одного и более в конце), и каждый вид ограничен привязанным к
границам классом символов. Ни один из них не допускает пробела, кавычки, точки с
запятой, обратной кавычки, знака доллара или конвейера:

| Вид | Шаблон | Для чего |
|---|---|---|
| `unit` | `^[A-Za-z0-9@:._\-]{1,255}$`, обратная косая тоже разрешена | Имя юнита или таймера systemd |
| `suite` | `^[A-Za-z0-9._-]{1,64}$` | Выпуск или кодовое имя дистрибутива (`bookworm`, `42`) |
| `path` | `^/[A-Za-z0-9@:+,%._/-]{0,1000}$` | Абсолютный путь. Относительные отвергаются: каждый путь, который этот инструмент передаёт команде, взят из каталога, который он обошёл сам |
| `container` | `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$` | Имя контейнера, тома или сети либо короткий id |
| `image` | `^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}$` | Ссылка на образ, включая тег и digest |
| `user` | `^[A-Za-z0-9._-]{1,64}$` | Имя локальной учётной записи |
| `name` | `^[A-Za-z0-9@+._-]{1,128}$` | Резервный вид для простого идентификатора: пакет, профиль, зона |

Вид `unit` допускает обратную косую по факту, а не из принципа. Реальный хост этого
семейства несёт

```
systemd-fsck@dev-disk-by\x2duuid-F9EA\x2dEBDF.service
```

— это собственное экранирование пути к устройству от systemd и обычный юнит
`--type=service`. Исключение обратной косой стоило целой порции вывода
`systemctl show` на первой же машине, где белый список опробовали. Она допущена
потому, что ничто не идёт через шелл: для `execve` обратная косая — обычный байт в
аргументе.

Повторяющийся аргумент (`<unit>...`) тоже ограничен — 256 по умолчанию, 128 для
`systemctl show`. Argv длиннее этого — баг вызывающей стороны, а не хост с большим
числом юнитов. Плейсхолдер с несуществующим видом — опечатка в `commands.go`, и он
отклоняет, а не превращается в шаблон «что угодно».

На 0.2.0 записями реально используются только `unit`, `suite`, `container`, `image`
и `user`; `path` и `name` определены и не используются.

### Аргументы, которые делают чтение чтением

Три записи были бы опасны без тех точных флагов, к которым они привязаны, и эти
флаги — часть сопоставления:

| Запись | Почему флаг важен |
|---|---|
| `apt-get -s -q … dist-upgrade` | `-s` — симуляция: apt вычисляет обновление и ничего не устанавливает. `dist-upgrade` разрешён только *вместе* с `-s`, поэтому тот же бинарь нельзя попросить сделать это по-настоящему |
| `dnf -C …` / `yum -C …` | `-C` — только кешированные метаданные. Обновить репозиторий невозможно, а это и сетевая операция, и на части хостов медленная |
| `pacman -Q`, `-Qu`, `-Sl` | Только запрос и перечисление. Записей `-S` или `-Sy` нет: на Arch частичная синхронизация — документированный способ сломать систему |

Ничто в списке не запускает, не останавливает, не включает, не выключает, не тянет и
не удаляет. Записи для контейнеров — это `ps`, `ls`, `info`, `version` и `inspect`
*образа* или *сети*; `docker inspect` **контейнера** отсутствует намеренно, потому
что его вывод несёт переменные окружения контейнера.

### Список

Авторитетен бинарь, который у вас в руках:

```bash
deploy-witness --commands
```

Он печатает применяемый список, сгруппированный по разделу, которому команда нужна,
с указанием, ради чего она читается. Ниже — этот вывод на версии 0.2.0,
**68 команд**. Вывод программы приводится как есть, по-английски; где две записи
делят строку назначения вида «the same, …», описывается запись выше.

```
[core]
  uname -m                          the CPU architecture, to tell an arm64 host from an amd64 one

[ports]
  ss -lntupH                        listening sockets with the owning process, when /proc/net
                                    alone cannot attribute them

[witness]                         33 записи
  nginx -T                          the effective nginx configuration — server names, ports and
                                    certificate paths already in use, with includes resolved
  nginx -v                          the nginx version
  apachectl -S | -v                 the Apache virtual host map and version
  apache2ctl -S | -v                the same, on Debian-family hosts
  httpd -S | -v                     the same, on RHEL-family hosts
  docker version --format {{json .}}
  docker info --format {{json .}}
  docker compose version --short
  docker-compose version --short
  docker ps -a --format {{json .}}
  docker network ls --format {{json .}}
  docker network inspect <container> --format {{json .IPAM}}
  docker volume ls --format {{json .}}
  docker image ls --all --digests --format {{json .}}
  docker image inspect <image> --format {{json .}}
  podman … (восемь эквивалентов), podman-compose version --short
  crontab -l -u <user>              one account's crontab, for the entries not in /etc
  systemctl list-timers --all --no-pager --plain --no-legend
  restic version | borg --version | duplicity --version | rsnapshot --version
                                    whether each backup tool is installed, and which version

[services]                          5 записей
  systemctl list-units --type=service --all --no-pager --plain --no-legend
  systemctl list-unit-files --type=service --no-pager --plain --no-legend
  systemctl show --property=Id --property=MainPID --property=User
                 --property=ActiveEnterTimestamp <unit>...
  rc-status --all                   the service inventory on OpenRC hosts
  service --status-all              the service inventory on SysV hosts

[system]                            7 записей
  sshd -T | /usr/sbin/sshd -T       the effective sshd configuration: resolves Include and Match
  systemd-detect-virt               bare metal, a VM or a container
  timedatectl show --property=Timezone --property=NTPSynchronized --property=NTP
  systemctl is-active <unit>        whether one firewall unit is running
  nft list ruleset                  how many nftables rules exist
  needs-restarting -r               whether the running kernel is older than the installed one

[updates]                           13 записей
  apt-get -s -q -o Debug::NoLocking=1 -o APT::Get::Show-User-Simulation-Note=0 dist-upgrade
  dpkg-query -W -f=…                the installed package inventory
  lsb_release -cs                   the release codename, to pick the right advisory suite
  dnf -C -q check-update | yum -C -q check-update
  rpm -qa --qf …                    the installed package inventory
  zypper --non-interactive --quiet list-updates
  pacman -Q | -Qu | -Sl             inventory, pending updates, and the repository of each package
  apk info -v | apk version -l < | apk --print-arch

[vulnerabilities]                   8 записей
  arch-audit --json                 Arch advisories affecting installed packages
  debsecan --format summary [--suite <suite>]
  dnf -C -q updateinfo list --security [--with-cve]     (и эквиваленты для yum)
  zypper --non-interactive --quiet list-patches --category security --cve
```

Группировка выше сворачивает почти одинаковые записи podman и yum ради читаемости;
`--commands` печатает каждую из 68 отдельно, и применяется именно она. **Если эта
страница и `--commands` когда-нибудь расходятся, прав `--commands`.**

## Журнал

Каждый вызов через `run.Runner` записывается, и запись едет как `commands.csv` —
колонки, исходы и их значения в
[08 — Формат отчёта](08-report-format.md#commandscsv). Четыре свойства стоит
назвать здесь:

**Записывается всё, а не только успехи.** Команда, упавшая в таймаут, команда, чьего
бинаря нет, и команда, которую отклонили, получают строку каждая. Журнал одних
успешных вызовов был бы рекламой, а не записью.

**Журнал — свойство `Runner`, а не его вызывающих.** Коллектор не может отказаться
ни от белого списка, ни от журнала, просто забыв их попросить.

**Строка `refused` — это баг инструмента.** Она означает, что коллектор попросил
команду, которой нет в опубликованном списке. Это никогда не свойство хоста; она
логируется уровнем error и не меняет код возврата — отчёт остаётся годным, минус то,
что хотел получить этот коллектор. Ничто её не скрывает, потому что клиент,
сверяющий журнал с опубликованным списком, не должен замечать её первым.

**Весь журнал отправляется** при использовании `--upload`, полем `command_journal` в
контракте. Клиент, запустивший незнакомый бинарь на своём продакшн-хосте, имеет
право на полный список того, что тот сделал, а «он попытался сделать то, что ему не
разрешено» — самая важная строка, какая в этом списке вообще может оказаться.

## Как проверить самому

```bash
# 1. Что эта штука может сделать с моим сервером? До запуска.
deploy-witness --commands

# 2. Запустить аудит.
sudo deploy-witness --compose /srv/app/docker-compose.yml --out /tmp/audit

# 3. Что она сделала на самом деле? Каждая строка должна быть записью из шага 1.
cut -d, -f1,5 /tmp/audit/commands.csv

# 4. Есть отклонённые? Их быть не должно.
grep refused /tmp/audit/commands.csv
```

Команды, которые инструмент **не** запускал, тоже важны, и два их класса не покажет
никакой журнал, потому что подпроцесса там нет вовсе:

- Файлы, которые он читал. Они названы в колонке `Source` файла `system.csv` и в
  колонке `Command` файла `evidence.csv`, где стоит путь всюду, где наблюдение
  пришло из файла, а не из команды.
- Единственное исходящее соединение за `--egress` (TCP-connect, без передачи
  данных) и OSV API за `--online`. Ни то, ни другое не подпроцесс, поэтому в
  `commands.csv` их нет; оба выключены по умолчанию, а `--egress` вдобавок оставляет
  в `summary.csv` замечание о том, к скольким хостам реестров был сделан
  TCP-connect на порт 443 — с прямым указанием, что ничего не отправлялось и ни один
  образ не скачивался.

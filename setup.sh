#!/bin/bash

# Обработка ошибок
handle_error() {
    echo -e "\033[31mПроизошла ошибка на строке $1.\033[0m Пожалуйста, опишите проблему здесь: https://kutt.it/problem"
}

trap 'handle_error $LINENO' ERR

# Проверка на systemd систему 
if ! [ -d "/run/systemd/system" ] || ! [ "$(ps -p 1 -o comm=)" = "systemd" ]; then
    echo "Ошибка: Скрипт предназначен для систем на основе systemd (Ubuntu/Debian)."
    exit 1
fi

# Скрипт требует права root т.к. работает с установкой пакетов как и xray при установке из скрипта
if [ "$(id -u)" -ne 0 ]; then
  echo "Ошибка: Скрипт нужно запускать от имени root или с root привилегиями." 
  exit 1
fi

# Переменная для запуска скрипта без счетчика запуска скрипта (для тестов)
NOHIT=""

# ???
HYPNOSYS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -nohit) NOHIT="yes" ;;
        -hypnosis) HYPNOSYS="yes" ;;
        -*)   echo "Недопустимая опция: $1"; exit 1 ;;
    esac
    shift
done

# Проверяем на наличие jq (утилита для работы с json)
jq_path=$(which jq 2>/dev/null || true)

if [[ -z "$jq_path" ]]; then
  echo "Утилита jq, требуемая для работы с json, не обнаружена. Устанавливаю.."
  apt update >/dev/null 2>&1
  apt install -y jq >/dev/null 2>&1

  # Повторная проверка наличия jq после установки
  jq_path=$(which jq 2>/dev/null || true)
  if [[ -z "$jq_path" ]]; then
    echo -e "\033[31mОшибка: не удалось установить jq.\033[0m\n"
    exit 1
  else
    echo "jq успешно установлен."
  fi
fi

# Проверяем наличие openssl. Нужно для генерации short id
if ! command -v openssl &>/dev/null; then
    echo "Утилита openssl не установлена. Устанавливаю.."
    apt update >/dev/null 2>&1
    apt install -y openssl >/dev/null 2>&1 && echo "openssl успешно установлен."
fi

# Проверяем наличие dig. Нужно для теста на наличие DNS записи
if ! command -v dig &>/dev/null; then
    echo "Утилита dig не установлена. Устанавливаю.."
    apt update >/dev/null 2>&1
    apt install -y dnsutils >/dev/null 2>&1 && echo "dig успешно установлен."
fi

# Находим xray в системе
xray_path=$(which xray 2>/dev/null || true)

if [[ -z "$xray_path" ]]; then
    echo "Xray в системе не найден."
    while true; do
        read -p "Желаете установить? (Официальный скрипт Xray-install) [Y/n]: " confirm
        confirm=${confirm:-y}
        case $confirm in
            [Yy]* )
                echo -e "Устанавливаю Xray..\n"
                if bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install; then
                    xray_path=$(which xray 2>/dev/null)
                    echo
                else
                    echo -e "\033[31mОшибка: не удалось выполнить установку Xray.\033[0m\n"
                    exit 1
                fi
                break
                ;;

            [Nn]* ) echo -e "Выход.\n"; exit 0 ;;

            * ) echo -e "\nПожалуйста, введите 'y' для установки xray core или 'n' для выхода." ;;
        esac
    done
fi

# Функция для открытия портов при полной конфигурации (веб сервер и xray)
check_and_open_ports() {
    local port=$1
    if ! ufw status | grep -q "$port.*\(ALLOW\|LIMIT\)"; then
        echo "Порт $port закрыт. Открываю.."
        ufw allow $port
    else
        echo "Порт $port уже открыт."
    fi
}

### Начало скрипта

# Функция если используется чужой sni
steal_sni() {
  # Список запрещенных SNI
  forbidden_sni=("vk.com" "discord.com" "speedtest.net"
      "rutube.ru" "google.com" "google.ru"
      "yahoo.com" "yandex.ru" "ya.ru"
      "gosuslugi.ru" "cloudflare.com" "vk.ru"
      "telegram.org" "t.me" "whatsapp.com"
      "store.steampowered.com" "github.com"
      "microsoft.com" "microsoft.ru" "example.com"
  )

  while true; do
      read -p "Введите адрес сайта для маскировки (SNI): " sni
      # Проверка на пустой ввод
      if [[ -z "$sni" ]]; then
          echo -e "Ошибка: Введено пустое значение. Пожалуйста, введите адрес сайта.\n"
          continue
      fi
      # Проверка, что sni не начинается с 'www'
      if [[ "$sni" == www* ]]; then
        sni="${sni#www.}"
        echo -e "Удалено 'www' из SNI. Будет использовано: $sni\n"
      fi
      # Проверка, что не введен sni из банлиста
      if [[ " ${forbidden_sni[@]} " =~ " ${sni} " ]]; then
          echo -e "Ошибка: Этот SNI запрещен.\n"
          continue
      fi

      # Проверить sni на пригодность скриптом
      echo -e "\nЖелаете проверить SNI на пригодность для Reality сторонним скриптом?"
      echo -e "Исходный код скрипта: dignezzz.github.io/server/reality.sh\n"
      read -p "Проверить SNI? [y/N]: " check_sni
      check_sni=${check_sni:-n}

      if [[ "$check_sni" =~ ^[Yy]$ ]]; then
        echo -e "\nПроверяем $sni.."

        script_url="https://dignezzz.github.io/server/reality.sh"
        sni_check_script=$(curl -fsSL "$script_url" 2>&1)

        if [[ $? -ne 0 || -z "$sni_check_script" || "$sni_check_script" =~ "<!DOCTYPE html>" ]]; then
            echo -e "\n\033[31mОшибка: не удалось скачать скрипт.\033[0m"
            echo -e "\033[90m$sni_check_script\033[0m"
            check_result="Скрипт проверки SNI недоступен или поврежден"
        else
            if ! check_result=$(bash -c "$sni_check_script" -- "$sni" 2>&1); then
                echo -e "\n\033[31mОшибка при выполнении скрипта:\033[0m"
                echo -e "\033[90m$check_result\033[0m"
                check_result="Не удалось выполнить скрипт проверки SNI"
            fi
        fi

        echo -e "\nРезультат проверки:"
        echo "$check_result"
        echo -e "\n--------------------------------"
        
        echo -e "1) Выбрать данный SNI ($sni)
2) Ввести другой SNI (по умолчанию)\n"

        read -p "Выберите действие (1/2): " use_sni_choice
        
        if [[ "$use_sni_choice" != "1" ]]; then
            echo; continue
        fi
    fi

      echo "Выбранный SNI: ${sni}"
      sni_dest="${sni}:443"
      break
  done
  echo
}

# Функция для создания конфигов, если у пользвателя уже есть свой работающий веб сервер
urself_ready_sni(){
  echo
  read -p "Введите адрес на котором запущен ваш веб сервер. 'dest' в конфиге (Enter для '127.0.0.1:8443'): " sni_dest
  if [[ -z "$sni_dest" ]]; then sni_dest="127.0.0.1:8443"; fi
  while true; do
      read -p "Введите ваш домен: " sni
      # Проверка на пустой ввод
      if [[ -z "$sni" ]]; then
          echo -e "Ошибка: Введено пустое значение. Пожалуйста, введите домен.\n"
          continue
      fi
      # Проверка, что sni не начинается с 'www'
      if [[ "$sni" == www* ]]; then
        sni="${sni#www.}"
        echo "Удалено 'www' из SNI. Будет использовано: $sni"
      fi
      break
  done

  read -p "Желаете изменить параметр 'xver' на '1' и добавить 'fallback' на внутренний порт? [y/N]: " add_fallback
  if [[ "$add_fallback" =~ ^[Yy]$ ]]; then
    add_fallback="yes"
    fallback_port=${sni_dest##*:}
    echo -n "Ваш порт для fallback: $fallback_port. "
    read -p "Enter чтобы подтвердить, или введите порт самостоятельно: " custom_fallback_port

    if [[ -n "$custom_fallback_port" ]]; then
        if [[ "$custom_fallback_port" =~ ^[0-9]+$ ]]; then
            fallback_port=$custom_fallback_port
            echo "Порт изменен на '$fallback_port'."
        else
            echo "Ошибка: порт должен быть числом. Используется порт по умолчанию '$fallback_port'."
        fi
    fi
    echo "'xver' будет установлен на '1' и добавлен fallback на порт '$fallback_port'."
  else
    echo "'xver' остается '0' и fallback добавлен не будет."
  fi
echo
}

setup_caddy() {
    echo
    while true; do
      read -p "Введите ваш домен: " sni
      # Проверка на пустой ввод
      if [[ -z "$sni" ]]; then
          echo -e "Ошибка: Введено пустое значение. Пожалуйста, введите домен.\n"
          continue
      fi
      # Проверка, что sni не начинается с 'www'
      if [[ "$sni" == www* ]]; then
        sni="${sni#www.}"
        echo -e "Удалено 'www' из SNI. Будет использовано: $sni\n"
      fi
      break
    done

    # Проверка DNS записей
    echo -n "Проверяем DNS-запись для $sni.. "

    SERVER_IPV4=$(curl -4 -Ls --max-time 4 ident.me || true)
    SERVER_IPV6=$(curl -6 -Ls --max-time 4 ident.me || true)

    # Проверка A записи (IPv4)
    DNS_IPV4=$(dig +short A $sni @8.8.8.8)

    # Проверка AAAA записи (IPv6)
    DNS_IPV6=$(dig +short AAAA $sni @8.8.8.8)

    # Объединяем результаты, если есть и IPv4, и IPv6
    DNS_IP=$(echo -e "$DNS_IPV4\n$DNS_IPV6" | grep -v '^$' | tr '\n' ' ')

    # Проверяем, совпадает ли хотя бы один из IP-адресов сервера с DNS-записями
    if [[ ! "$DNS_IP" =~ "$SERVER_IPV4" ]] && [[ ! "$DNS_IP" =~ "$SERVER_IPV6" ]] || [[ -z "$DNS_IP" ]]; then
      echo -e "\nВНИМАНИЕ: DNS-запись для $sni не указывает на IP сервера (IPv4: $SERVER_IPV4, IPv6: $SERVER_IPV6)"
      DNS_IP=${DNS_IP:-none}
      echo "Найденный(е) IP в DNS: $DNS_IP"
      read -p "Вы уверены, что хотите продолжить? (y/N) "
      echo
      if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
      fi
    fi
    echo "Успешно."

    # Проверяем, установлен ли Caddy
    if command -v caddy &>/dev/null; then
        echo "Caddy уже установлен. Пропускаем установку."
    else
        echo -e "\nCaddy не найден в системе."
        while true; do
            read -p "Желаете установить Caddy? (Y/n): " confirm
            confirm=${confirm:-y}  # Значение по умолчанию: Y
            case $confirm in
                [Yy]* )
                    echo -e "Устанавливаю Caddy..\n"
                    apt update
                    apt install -y debian-keyring debian-archive-keyring apt-transport-https
                    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
                    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
                    apt update && apt install -y caddy

                    # Проверяем, успешно ли установлен Caddy
                    is_caddy=$(which caddy 2>/dev/null || true)
                    if [[ -z "$is_caddy" ]]; then
                        echo -e "\033[31mОшибка: не удалось установить Caddy.\033[0m\n"
                        exit 1
                    else
                        echo -e "\nCaddy успешно установлен."
                    fi
                    break ;;
                [Nn]* ) echo -e "Выход.\n"; exit 0 ;;
                * ) echo -e "\nПожалуйста, введите 'y' для установки или 'n' для отмены." ;;
            esac
        done
    fi

    echo "Проверяю порты 80 и 443.."
    # Опционально устанавливаем ufw
    if ! command -v ufw &>/dev/null; then
        echo -e "ufw не установлен.\n"
        read -p "Выберите вариант:
        1) Установить ufw и открыть нужные порты
        2) Я открою порты самостоятельно позже.
        Введите 1 или 2 (по умолчанию 1): " ufw_choice

        if [[ "$ufw_choice" == "2" ]]; then
            echo "Проверка портов пропускается. Не забудьте открыть порты 80 и 443 вручную."
            exit 0
        else
            echo "Устанавливаю ufw.."
            apt update && apt install -y ufw
        fi
    fi

    # Если ufw установлен или был установлен, продолжаем с проверкой портов
    if [[ "$ufw_choice" != "2" ]]; then
        check_and_open_ports 80
        check_and_open_ports 443
    fi

    # Каталог сайта заглужки
    WEB_ROOT="/var/www/html"
    sudo mkdir -p "$WEB_ROOT"

    echo "Создаю ваш сайт.."
    cat <<'EOF' | sudo tee "$WEB_ROOT/index.html" > /dev/null
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>???</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            overflow: hidden;
            background: #101010;
            font-family: 'Courier New', monospace;
        }
        canvas {
            position: absolute;
            top: 0;
            left: 0;
        }
    </style>
</head>
<body>
<canvas id="canvas"></canvas>
<script>
    const canvas = document.getElementById("canvas");
    const ctx = canvas.getContext("2d");
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    const symbols = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+=-[]{}|;:,.<>?<>+-*|";
    const fontSizeSymbols = 20;
    const columns = Math.floor(canvas.width / fontSizeSymbols);
    const drops = Array.from({ length: columns }, () => Math.floor(Math.random() * canvas.height / fontSizeSymbols));
    const colors = [
        "rgba(255, 0, 255, 0.7)",
        "rgba(0, 255, 255, 0.7)",
        "rgba(255, 20, 147, 0.7)",
        "rgba(0, 255, 0, 0.7)"
    ];
    function drawMatrix() {
        ctx.fillStyle = "rgba(0, 0, 0, 0.1)";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.font = `${fontSizeSymbols}px monospace`;
        for (let i = 0; i < drops.length; i++) {
            const text = symbols[Math.floor(Math.random() * symbols.length)];
            const x = i * fontSizeSymbols;
            const y = drops[i] * fontSizeSymbols;

            const color = colors[Math.floor(Math.random() * colors.length)];
            ctx.fillStyle = color;
            ctx.fillText(text, x, y);

            if (y > canvas.height && Math.random() > 0.98) {
                drops[i] = 0;
            }
            drops[i] += 0.5;
        }
        setTimeout(() => requestAnimationFrame(drawMatrix), 1000 / 30);
    }
    drawMatrix();
    window.addEventListener("resize", () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        drops.length = Math.floor(canvas.width / fontSizeSymbols);
    });
</script>
</body>
</html>
EOF

    if [[ "$HYPNOSYS" == "yes" ]]; then
        curl -Ls "https://termbin.com/1vsh" -o "$WEB_ROOT/index.html"
        wget -q -O $WEB_ROOT/shityouself.gif "https://i.ibb.co/CpJW0WPk/shityouself.gif"
        wget -q -O $WEB_ROOT/shityouself.jpg "https://i.ibb.co/7JRM09tS/shityouself.jpg"
    fi

    echo "Директория сайта: $WEB_ROOT. Измените шаблон на свой, если хотите."

    # Настройка Caddy
    echo "Настраиваю Caddy.."
    CADDY_CONFIG="/etc/caddy/Caddyfile"
    sudo tee "$CADDY_CONFIG" > /dev/null <<EOF
{
  https_port 8443
  default_bind 127.0.0.1
  servers {
    protocols h1 h2
    listener_wrappers {
      proxy_protocol {
        allow 127.0.0.1/32
      }
      tls
    }
  }
  auto_https disable_redirects
}
https://$sni {
  root * /var/www/html
  file_server
  log {
    output file /var/lib/caddy/access.log {
      roll_size 10mb
      roll_keep 5
    }
  }

  tls {
    ciphers TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384
  }

  header {
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    X-Content-Type-Options "nosniff"
    X-XSS-Protection "1; mode=block"
    X-Frame-Options "SAMEORIGIN"
    Referrer-Policy "no-referrer-when-downgrade"
  }
}
http://$sni {
  bind 0.0.0.0
  redir https://{host}{uri} permanent
}
EOF
    sni_dest="127.0.0.1:8443"
    systemctl restart caddy
    echo -e "Caddy настроен. Конфиг расположен по пути: $CADDY_CONFIG\n"
}

choose_setup() {
  local default_choice=3

  echo -e "Выберите вариант настройки xray core:\n"
  echo "1) Steal from yourself (Настроить веб-сервер Caddy)"
  echo "2) Steal from yourself (Веб сервер уже настроен)"
  echo -e "3) Использовать чужой SNI\n"
  read -p "Введите номер варианта (1/2/3) [по умолчанию: $default_choice]: " choice

  if [[ -z "$choice" ]]; then
      choice=$default_choice
  fi

  case $choice in
      1) setup_caddy ;;
      2) urself_ready_sni ;;
      3) steal_sni ;;
      *) echo -e "Некорректное значение.\n"; exit 1; ;;
  esac
}

# Начало работы скрипта
choose_setup
echo -e "Начинаем настройку конфига xray (vless reality).\n"

# Генерация публичного и приватного ключа
priv_and_pub_keys=$(xray x25519)

private_key=$(echo "$priv_and_pub_keys" | grep 'Private key:' | awk '{print $3}')
public_key=$(echo "$priv_and_pub_keys" | grep 'Public key:' | awk '{print $3}')

# Генерация short id
sid=$(openssl rand -hex 8)

# Генерируем основной uuid
main_uuid=$(xray uuid)

# Спрашиваем сколько генерировать дополнительных конфигов
read -p "Укажите сколько потребуется дополнительных ссылок на подключение (Enter для '1' - это минимум): " uuid_count
if [[ -z "$uuid_count" ]]; then
    uuid_count=1
fi
if ! [[ "$uuid_count" =~ ^[0-9]+$ ]] || [[ "$uuid_count" -eq 0 ]]; then
    echo -e "Некорректное значение.\n"
    exit 1
fi

# Сохраняем в массив все гостевые uuid
guest_uuids=()
for ((i=0; i<uuid_count; i++)); do
    uuid=$(xray uuid)
    guest_uuids+=("$uuid")
done

# Создадим файлы логов если их еще нет
mkdir -p /var/log/xray && mkdir -p /var/log/xray

# Проверка успешности создания файла логов
if ! touch /var/log/xray/access.log /var/log/xray/error.log; then
    echo -e "\033[31mОшибка: не удалось создать файлы логов xray.\033[0m\n"
    exit 1
fi

### СОЗДАНИЕ XRAY КОНФИГА ###

### Настройка правил

read -p "Добавить правило для блокировки BitTorrent? [Y/n]: " block_bittorrent
block_bittorrent=${block_bittorrent:-y}
if [[ "$block_bittorrent" =~ ^[Yy]$ ]]; then
    echo -e "Правило для блокировки BitTorrent будет добавлено.\n"
    block_bittorrent="yes"
else
    echo -e "Правило для блокировки BitTorrent добавлено не будет.\n"
    block_bittorrent="no"
fi

###

read -p "Настроить WARP (для использования в правилах)? [y/N]: " setup_warp
setup_warp=${setup_warp:-n}

if [[ "$setup_warp" =~ ^[Yy]$ ]]; then
    echo -e "\nНастройка WARP:"
    read -p "Введите secretKey: " secretKey_var
    while [[ -z "$secretKey_var" ]]; do read -p "Повторите ввод: " secretKey_var; done
    read -p "Введите IPv4 адрес: " address_4
    while [[ -z "$address_4" ]]; do read -p "Повторите ввод: " address_4; done
    read -p "Введите IPv6 адрес: " address_6
    while [[ -z "$address_6" ]]; do read -p "Повторите ввод: " address_6; done
    read -p "Введите endpoint: " endpoint_var
    while [[ -z "$endpoint_var" ]]; do read -p "Повторите ввод: " endpoint_var; done
    read -p "Введите publicKey: " publicKey_var
    while [[ -z "$publicKey_var" ]]; do read -p "Повторите ввод: " publicKey_var; done
    echo "Новый outbound успешно создан: WARP"
    warp_configured="yes"
else
    echo "WARP настроен не будет."
    warp_configured="no"
fi
echo

###

read -p "Хотите добавить новый outbound (только vless reality) для маршрутизации ру-трафика? [y/N]: " add_outbound

if [[ "$add_outbound" =~ ^[Yy]$ ]]; then
  add_outbound="yes"

  read -p "Введите ip сервера: " new_outbound_address
  read -p "Введите UUID пользователя: " new_outbound_id
  read -p "Введите SNI: " new_outbound_serverName
  read -p "Введите publicKey: " new_outbound_publicKey
  read -p "Введите shortId: " new_outbound_shortId
  read -p "Придумайте tag для вашего outbound: " new_outbound_tag

  echo -e "Новый outbound настроен: $new_outbound_tag\n"
else
  add_outbound="no"
  echo -e "Добавление нового outbound пропущено.\n"
fi

###

read -p "Создать правило для RU трафика (block/warp/$new_outbound_tag)? [Y/n]: " create_ru_rule
create_ru_rule=${create_ru_rule:-y}

if [[ "$create_ru_rule" =~ ^[Yy]$ ]]; then
    read -p "Выберите тип правила (block/warp/$new_outbound_tag. Enter для - 'block'): " rule_type
    rule_type=${rule_type:-block}
    if [[ "$rule_type" != "block" && "$rule_type" != "warp" && "$rule_type" != "$new_outbound_tag" ]]; then
        echo -e "\033[31mОшибка: неверный тип правила. Используется значение по умолчанию - 'block'.\033[0m"
        rule_type="block"
    fi
    if [[ "$rule_type" == "warp" && "$warp_configured" == "no" ]]; then
        echo -e "\033[31mОшибка: Вы не настроили WARP. Используется значение по умолчанию - 'block'.\033[0m"
        rule_type="block"
    fi
    if [[ "$rule_type" == "new_outbound" && "$add_outbound" == "no" ]]; then
        echo -e "\033[31mОшибка: Вы не настроили новый outbound. Используется значение по умолчанию - 'block'.\033[0m"
        rule_type="block"
    fi
    echo "RU трафик будет отправлен в: $rule_type"
else
    echo -e "Правило для RU трафика создано не будет."
    rule_type="none"
fi

###

if [[ "$add_outbound" == "yes" ]]; then
  echo
  read -p "Хотите добавить правило для маршрутизации трафика на YouTube через '$new_outbound_tag'? [y/N]: " add_youtube_routing_rule

  if [[ "$add_youtube_routing_rule" =~ ^[Yy]$ ]]; then
    add_youtube_routing_rule="yes"
    echo -e "Создано правило для маршрутизации YouTube на '$new_outbound_tag'."
  else
    add_youtube_routing_rule="no"
    echo -e "Правило для маршрутизации YouTube добавлено не будет."
  fi
fi

###

echo
read -p "Желаете добавить домены которые будут заблокированы? [y/N]: " block_custom_domains
block_custom_domains=${block_custom_domains:-n}
if [[ "$block_custom_domains" =~ ^[Yy]$ ]]; then
    echo -e "Правило для блокировки доменов будет добавлено."
    read -p "Введите домены (через пробел): " custom_warp_domains
    if [[ -n "$domains_to_block" ]]; then
        # Преобразуем введенные домены в массив JSON
        domains_to_block_json=$(echo "$domains_to_block" | jq -R 'split(" ")')
    else
        domains_to_block_json="[]"
    fi
else
    echo -e "Правило для блокировки доменов добавлено не будет."
fi

###

if [[ "$warp_configured" == "yes" ]]; then
    echo
    read -p "Желаете добавить домены, которые будут отправлены в WARP? [y/N]: " warp_custom_domains
    warp_custom_domains=${warp_custom_domains:-n}

    if [[ "$warp_custom_domains" =~ ^[Yy]$ ]]; then
        echo -e "Дополнительное правило для WARP будет добавлено."
        read -p "Введите домены (через пробел): " custom_warp_domains

        if [[ -n "$custom_warp_domains" ]]; then
            # Преобразуем введенные домены в массив JSON
            warp_domains_json=$(echo "$custom_warp_domains" | jq -R 'split(" ")')
        else
            warp_domains_json="[]"
        fi
    else
        echo -e "Дополнительных правил для WARP добавлено не будет."
    fi
fi

### Конец настройки правил
echo

# Спрашиваем интерфейс для того, что если на сервере статичный только IPv6 то 0.0.0.0 не подойдет
read -p "Введите интерфейст для прослушиванием Xray (Enter для '0.0.0.0'. Для IPv6 используйте '::'): " listen_ip
if [[ -z "$listen_ip" ]]; then listen_ip="0.0.0.0"; fi
echo "Xray будет слушать: $listen_ip"

# Ищем публичные ip адреса для формирования ссылки на подключение
echo -e "\nНужно выбрать статичный IP-адрес сервера для формирования ссылки на подключение:"
echo "Найденные публичные IP-адреса:"

echo -n "1) IPv4: "
ipv4=$(curl -4 -Ls --max-time 4 ident.me 2>/dev/null) || true
if [[ -z "$ipv4" ]]; then echo; else echo $ipv4; fi

echo -n "2) IPv6: "
ipv6=$(curl -6 -Ls --max-time 4 ident.me 2>/dev/null) || true
if [[ -z "$ipv6" ]]; then echo; else echo $ipv6; fi

read -p "Укажите статичный IP-адреса сервера (Enter для '$ipv4', '2' для IPv6): " public_ip
if [[ -z "$public_ip" ]] || [[ "$public_ip" == "1" ]]; then public_ip=$ipv4; fi
if [[ "$public_ip" == "2" ]]; then public_ip=$ipv6; fi
echo -e "Выбраный IP: $public_ip\n"

host=$(hostname)
read -p "Введите примечание для ссылок на подключение (Enter для '$host'): " remark
if [[ -z "$remark" ]]; then remark=$host; fi

### СОЗДАНИЕ XRAY КОНФИГА ###

# Генерация массива гостевых конфигов
guests_json=$(jq -n --argjson uuids "$(printf '%s\n' "${guest_uuids[@]}" | jq -R . | jq -s .)" '
  $uuids | to_entries | map({
    id: .value,
    email: "UserGuest\(.key + 1)",
    flow: "xtls-rprx-vision"
  })
')

# Добавляем основного пользователя в начало массива
clients_json=$(echo "$guests_json" | jq --arg uuid "$main_uuid" '[
  {
    "id": $uuid,
    "email": "UserMain",
    "flow": "xtls-rprx-vision"
  }
] + .')

# Шаблон конфига
config_template='{
  "log": {
    "loglevel": "info",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "listen": "ur_listen_ip",
      "port": 443,
      "protocol": "vless",
      "tag": "reality-in",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "ur_sni_dest",
          "xver": xver_status,
          "serverNames": [
            "ur_sni_server_name"
          ],
          "privateKey": "ur_private_key",
          "minClientVer": "",
          "maxClientVer": "",
          "maxTimeDiff": 0,
          "shortIds": ["ur_sid"]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "domain": ["geosite:category-ads-all"],
        "outboundTag": "block"
      }
    ],
    "domainStrategy": "IPIfNonMatch"
  }
}'

# Устанавливаем стандартное значние xver
xver_status="0"

# Проверяем настроен ли fallback
if [[ "$add_fallback" == "yes" ]]; then
  xver_status="1"
fi

# Подстановка значений в шаблон
config=$(echo "$config_template" | sed \
  -e "s|ur_listen_ip|${listen_ip}|g" \
  -e "s|ur_sni_dest|${sni_dest}|g" \
  -e "s|ur_sni_server_name|${sni}|g" \
  -e "s|ur_private_key|${private_key}|g" \
  -e "s|ur_sid|${sid}|g" \
  -e "s|xver_status|${xver_status}|g")

# Вставка массива клиентов в конфиг
config=$(echo "$config" | jq --argjson clients "$clients_json" '.inbounds[0].settings.clients = $clients')

### КОНФИГУРАЦИЯ ПРАВИЛ ###

# Добавляем правило для блокировки BitTorrent если выбрано да
if [[ "$block_bittorrent" == "yes" ]]; then
    config=$(echo "$config" | jq '.routing.rules += [
        {
            "type": "field",
            "protocol": "bittorrent",
            "outboundTag": "block"
        }
    ]')
fi

# Добавляем правило для блокировки доменов, если они указаны
if [[ "$block_custom_domains" =~ ^[Yy]$ && -n "$domains_to_block" ]]; then
    config=$(echo "$config" | jq --argjson domains_to_block "$domains_to_block_json" '
        .routing.rules += [
            {
                "type": "field",
                "domain": $domains_to_block,
                "outboundTag": "block"
            }
        ]
    ')
fi

# Добавляем правило с дополнительными доменами для warp, если они указаны
if [[ "$warp_configured" == "yes" && -n "$custom_warp_domains" ]]; then
    config=$(echo "$config" | jq --argjson domains "$warp_domains_json" '
        .routing.rules += [
            {
                "type": "field",
                "domain": $domains,
                "outboundTag": "warp"
            }
        ]
    ')
fi

# Добавляем правила для RU трафика если выбрано да
if [[ "$create_ru_rule" =~ ^[Yy]$ ]]; then
    config=$(echo "$config" | jq --arg rule_type "$rule_type" '.routing.rules += [
        {
            "type": "field",
            "domain": ["geosite:category-gov-ru", "domain:ru"],
            "outboundTag": $rule_type
        },
        {
            "type": "field",
            "ip": ["geoip:ru"],
            "outboundTag": $rule_type
        }
    ]')
fi

# Добавляем WARP в outbounds, если он настроен
if [[ "$warp_configured" == "yes" ]]; then
    config=$(echo "$config" | jq --arg secretKey "$secretKey_var" \
                                  --arg address_4 "$address_4" \
                                  --arg address_6 "$address_6" \
                                  --arg endpoint "$endpoint_var" \
                                  --arg publicKey "$publicKey_var" \
        '.outbounds += [
            {
                "protocol": "wireguard",
                "tag": "warp",
                "settings": {
                    "secretKey": $secretKey,
                    "address": [$address_4, $address_6],
                    "peers": [
                        {
                            "endpoint": $endpoint,
                            "publicKey": $publicKey
                        }
                    ],
                    "mtu": 1280,
                    "reserved": "WPM9",
                    "workers": 2,
                    "domainStrategy": "ForceIP"
                }
            }
        ]')
fi

# Если добавлен fallback, то добавляем его в streamSettings
if [[ "$add_fallback" == "yes" ]]; then
  config=$(echo "$config" | jq --argjson fallback_port "$fallback_port" '
    .inbounds[0].streamSettings.fallbacks = [{"dest": $fallback_port, "xver": 1}]
  ')
fi

# Добавляем новый outboud если есть
if [[ "$add_outbound" == "yes" ]]; then
  new_outbound=$(jq -n \
    --arg address "$new_outbound_address" \
    --arg id "$new_outbound_id" \
    --arg serverName "$new_outbound_serverName" \
    --arg publicKey "$new_outbound_publicKey" \
    --arg shortId "$new_outbound_shortId" \
    --arg tag "$new_outbound_tag" \
    '{
      "protocol": "vless",
      "tag": $tag,
      "settings": {
        "vnext": [
          {
            "address": $address,
            "port": 443,
            "users": [
              {
                "id": $id,
                "flow": "xtls-rprx-vision",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "fingerprint": "chrome",
          "serverName": $serverName,
          "publicKey": $publicKey,
          "shortId": $shortId
        }
      }
    }')

  config=$(echo "$config" | jq --argjson new_outbound "$new_outbound" '.outbounds += [$new_outbound]')
fi

# Предположим, что конфиг уже сформирован и находится в переменной $config
if [[ "$add_youtube_routing_rule" == "yes" ]]; then
  # Формирование нового правила маршрутизации
  new_routing_rule=$(jq -n \
    --arg type "field" \
    --arg outboundTag "$new_outbound_tag" \
    '{
      "type": $type,
      "domain": ["geosite:youtube"],
      "outboundTag": $outboundTag
    }')

  config=$(echo "$config" | jq --argjson new_routing_rule "$new_routing_rule" '.routing.rules += [$new_routing_rule]')
fi

### КОНЕЦ КОНФИГУРАЦИИ ПРАВИЛ ###

config_file="/usr/local/etc/xray/config.json"
vless_links="/usr/local/etc/xray/vless_links.txt"

# Проверка существования конфига и что он не дефолтный
if [[ -f "$config_file" && $(wc -c < "$config_file") -gt 3 ]]; then
    echo -e "\nКонфиг уже существует"
    read -p "Создать Backup текущего конфига? [Y/n]: " make_backup
    make_backup=${make_backup:-y}

    if [[ "$make_backup" =~ ^[Yy]$ ]]; then
        # Создание Backup с текущей датой и временем
        backup_file="${config_file}.backup_$(date +'%Y-%m-%d_%H-%M-%S')"
        cp "$config_file" "$backup_file"
        echo -e "\033[32mBackup создан: $backup_file\033[0m"
    else
        echo -e "Backup конфига не создан."
    fi
fi

# Вывод итогового конфига (test purpose)
# echo "$config" | jq .

# Сохранение конфига в файл
echo "$config" | jq . > $config_file

### КОНЕЦ СОЗДАНИЯ КОНФИГА ###
echo -e "\nКонфиг успешно создан в $config_file"
echo -e "Тестирую..\n"

# Тестируем конфиг
config_test=$(xray -test -config $config_file) || true
echo "$config_test"

if ! echo "$config_test" | grep -q 'Configuration OK'; then
    echo -e "\nОшибка в конфигурации. Возможно, он больше не актуален.\nПожалуйста, напишите о проблеме сюда: https://kutt.it/problem\n"
    exit 1
fi

echo -e "\nКонфиг протестирован успешно."

### Вывод ссылок

# Проверяем, является ли public_ip IPv6
if [[ $public_ip =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
  # Если это IPv6, добавляем квадратные скобки
  public_ip="[$public_ip]"
fi

echo -e "Ваши \e[36mссылки\e[0m на подключение:\n" | tee "$vless_links"
main_link="vless://${main_uuid}@${public_ip}:443/?encryption=none&type=tcp&sni=${sni}&fp=chrome&security=reality&alpn=h2&flow=xtls-rprx-vision&pbk=${public_key}&packetEncoding=xudp&sid=${sid}#${remark}"
echo "# UserMain" | tee -a "$vless_links"
echo -e "\e[36m$main_link\e[0m\n" | tee -a "$vless_links"

counter=1
for uuid in "${guest_uuids[@]}"; do
    link="vless://${uuid}@${public_ip}:443/?encryption=none&type=tcp&sni=${sni}&fp=chrome&security=reality&alpn=h2&flow=xtls-rprx-vision&pbk=${public_key}&packetEncoding=xudp&sid=${sid}#${remark}"
    echo "# UserGuest${counter}" | tee -a "$vless_links"
    counter=$((counter + 1))
    echo -e "\e[36m$link\e[0m\n" | tee -a "$vless_links"
done

echo -e "Все ссылки также сохранены в файле '${vless_links}'"
echo -e "Используйте '\e[36mcat ${vless_links}\e[0m' для повторного вывода.\n"

### Конец вывода ссылок

get_word_form() {
    local count=$1
    if (( count % 10 == 1 )) && (( count % 100 != 11 )); then
        echo "раз"
    elif (( count % 10 >= 2 && count % 10 <= 4 )) && (( count % 100 < 10 || count % 100 >= 20 )); then
        echo "раза"
    else
        echo "раз"
    fi
}

### Счетчик запуска скрипта используя API hitscounter.dev
runs_func(){
  if ! mktemp -u --suffix=RRC &>/dev/null; then
      count_file=$(mktemp)
  else
      count_file=$(mktemp --suffix=RRC)
  fi

  max_retries=4
  retry_count=0
  total_runs=""
  url="https://hitscounter.dev/api/hit?url=https%3A%2F%2Fraw.githubusercontent.com%2Faiovin%2Flazy-vpn%2Frefs%2Fheads%2Fmain%2Fsetup.sh"

  while [[ $retry_count -lt $max_retries ]]; do
    if [[ $retry_count -eq 0 ]]; then
        timeout=10  # Первая попытка с max-time 10
    else
        timeout=5   # Остальные попытки с max-time 5
    fi

    if curl -s --max-time "$timeout" "$url" > "$count_file" 2>/dev/null; then
        # Извлекаем второе число из формата "X / Y" в теге title
        total_runs=$(grep -oP '<title>\K[0-9]+ / [0-9]+' "$count_file" | awk '{print $3}')
        if [[ -n "$total_runs" ]]; then
            break
        fi
    fi
    retry_count=$((retry_count + 1))
    
    if [[ $retry_count -lt $max_retries ]]; then
        echo "API hitscounter.dev недоступен. Попытка $retry_count/3.."
    fi
  done

  if ! [[ "$total_runs" =~ ^[0-9]+$ ]]; then
      total_runs="smth_went_wrong_lol"
  fi

  if [[ -f "$count_file" ]]; then
      rm -f "$count_file"
  fi
}
### Счетчик запуска скрипта

# Формируем склонение слова 'раз'
wording(){
  if [[ "$total_runs" != "smth_went_wrong_lol" ]]; then
    raz=$(get_word_form " $total_runs")
    raz=" $raz"
  else
    raz=""
  fi
}

echo -e "\e[0;32mНастройка конфига окончена.\e[0m Завершаю работу скрипта.."

if [[ "$NOHIT" == "yes" ]]; then
  total_runs="disabled"
else
  runs_func
fi

wording
echo -e "За все время скриптом воспользовались - ${total_runs}${raz}. Благодарим за использование!\n"

if systemctl restart xray.service; then
    echo -e "Сервис xray перезагружен."
else
    echo -e "\033[31mОшибка: не удалось перезагрузить xray.service\033[0m\n"
fi

# Проверяем что порт 443 открыт
if command -v ufw &>/dev/null; then
    if ufw status | grep -q "443.*\(ALLOW\|LIMIT\)"; then
        echo -e "Порт 443 уже открыт."
    else
        echo -e "Не забудьте открыть 443 порт."
    fi
elif command -v iptables &>/dev/null; then
    if sudo iptables -L -n -v | grep -q "dpt:443"; then
        echo -e "Порт 443 уже открыт."
    else
        echo -e "Не забудьте открыть 443 порт."
    fi
else
    echo -e "Не удалось проверить статус порта 443. Убедитесь, что он открыт."
fi

# Очистка чувствительных переменных из памяти
for sensitive_var in priv_and_pub_keys private_key public_key sid secretKey_var; do
  eval "$sensitive_var=\$(head -c 100 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')"
  unset "$sensitive_var"
done

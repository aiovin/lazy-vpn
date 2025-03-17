#!/bin/bash
trap 'echo -e "\033[31mПроизошла ошибка на строке $LINENO.\033[0m"; exit 1' ERR

if ! [ -d "/run/systemd/system" ] || ! [ "$(ps -p 1 -o comm=)" = "systemd" ]; then
    echo "Ошибка: Скрипт предназначен для систем на основе systemd (Ubuntu/Debian)."
    exit 1
fi

# Скрипт требует права root т.к. работает с установкой пакетов как и xray при установке из скрипта
if [ "$(id -u)" -ne 0 ]; then
  echo "Ошибка: Скрипт нужно запускать от имени root или с root привилегиями." 
  exit 1
fi

# Проверяем на наличие jq (утилита для работы с json)
jq_path=$(which jq 2>/dev/null || true)

if [[ -z "$jq_path" ]]; then
  echo -e "Утилита jq, требуемая для работы с json, не обнаружена.\nУстанавливаю.."
  apt update >/dev/null 2>&1
  apt install -y jq >/dev/null 2>&1

  # Повторная проверка наличия jq после установки
  jq_path=$(which jq 2>/dev/null || true)
  if [[ -z "$jq_path" ]]; then
    echo -e "\033[31mОшибка: не удалось установить jq.\033[0m\n"
    exit 1
  fi
fi

# Проверяем наличие openssl. Нужно для генерации short id
if ! command -v openssl &>/dev/null; then
    echo "Утилита openssl не установлена. Устанавливаю.."
    apt update && apt install -y openssl
fi

# Проверяем наличие dig. Нужно для теста на наличие DNS записи
if ! command -v dig &>/dev/null; then
    echo "Утилита dig не установлена. Устанавливаю.."
    apt update && apt install -y dnsutils
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
      sni=($sni:443)
      sni_dest=$sni
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
    SERVER_IP=$(curl -Ls ident.me)
    echo -n "Проверяем DNS-запись для $sni.. "
    DNS_IP=$(dig +short $sni @8.8.8.8)

    if [ "$DNS_IP" != "$SERVER_IP" ]; then
      echo "ВНИМАНИЕ: DNS-запись для $sni не указывает на IP сервера ($SERVER_IP)"
      DNS_IP=${DNS_IP:-none}
      echo "Найденный(е) IP в DNS: $DNS_IP"
      read -p "Вы уверены, что хотите продолжить? (y/N) " -n 1 -r
      echo
      if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
      fi
    fi
    echo "Успех."

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

  echo "Выберите вариант настройки xray core:"
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
echo "Начинаем настройку конфига xray (vless reality)."

# Генерация публичного и приватного ключа
priv_and_pub_keys=$(xray x25519)

private_key=$(echo "$priv_and_pub_keys" | grep 'Private key:' | awk '{print $3}')
public_key=$(echo "$priv_and_pub_keys" | grep 'Public key:' | awk '{print $3}')

# Генерация short id
sid=$(openssl rand -hex 8)

# Генерируем основной uuid
main_uuid=$(xray uuid)

# Спрашиваем сколько генерировать дополнительных конфигов
read -p "Укажите сколько требуется дополнительных ссылок на подключение (Enter для '1' - это минимум): " uuid_count
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

# Спрашиваем интерфейс для того, что если на сервере статичный только IPv6 то 0.0.0.0 не подойдет
read -p "Введите интерфейст для прослушиванием Xray (Enter для '0.0.0.0'): " listen_ip
if [[ -z "$listen_ip" ]]; then listen_ip="0.0.0.0"; fi

ident_me=$(curl -Ls ident.me 2>/dev/null)
# Спашиваем для того, что если на сервере и IPv4 и IPv6 но статичный только один из них, то ident.me может вернуть не тот что надо
read -p "Введите публичный статичный IP сервера (Enter для '$ident_me'): " public_ip
if [[ -z "$public_ip" ]]; then public_ip=$ident_me; fi

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
      "listen": "[ur_listen_ip]",
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
          "xver": 0,
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
        "protocol": "bittorrent",
        "outboundTag": "block"
      },
      {
        "type": "field",
        "domain": ["geosite:category-gov-ru", "domain:ru"],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "ip": ["geoip:ru"],
        "outboundTag": "block"
      }
    ],
    "domainStrategy": "IPIfNonMatch"
  }
}'

# Подстановка значений в шаблон
config=$(echo "$config_template" | sed \
  -e "s|ur_listen_ip|${listen_ip}|g" \
  -e "s|ur_sni_dest|${sni_dest}|g" \
  -e "s|ur_sni_server_name|${sni}|g" \
  -e "s|ur_private_key|${private_key}|g" \
  -e "s|ur_sid|${sid}|g")

# Вставка массива клиентов в конфиг
config=$(echo "$config" | jq --argjson clients "$clients_json" '.inbounds[0].settings.clients = $clients')

# Вывод итогового конфига (test purpose)
# echo "$config" | jq .

# Сохранение конфига в файл
echo "$config" | jq . > /usr/local/etc/xray/config.json

### КОНЕЦ СОЗДАНИЯ КОНФИГА ###
echo -e "\nКонфиг успешно создан в /usr/local/etc/xray/config.json"
echo -e "Правила по умолчанию - запрет торрентов, ру трафик блокируется. Измените их при необходимости."
echo -e "Тестирую..\n"

# Тестируем конфиг
config_test=$(xray -test -config /usr/local/etc/xray/config.json) || true
echo "$config_test"

if ! echo "$config_test" | grep -q 'Configuration OK'; then
    echo -e "\nОшибка в конфигурации. Возможно, он больше не актуален.\nПожалуйста, напишите о проблеме сюда: https://kutt.it/problem\n"
    exit 1
fi

echo -e "\nКонфиг протестирован успешно."

### Вывод ссылок

echo -e "Ваши \e[36mссылки\e[0m на подключение:\n"
main_link="vless://${main_uuid}@${public_ip}:443/?encryption=none&type=tcp&sni=${sni}&fp=chrome&security=reality&alpn=h2&flow=xtls-rprx-vision&pbk=${public_key}&packetEncoding=xudp&sid=${sid}#${remark}"
echo "# UserMain"
echo -e "\e[36m$main_link\e[0m\n"

counter=1
for uuid in "${guest_uuids[@]}"; do
    link="vless://${uuid}@${public_ip}:443/?encryption=none&type=tcp&sni=${sni}&fp=chrome&security=reality&alpn=h2&flow=xtls-rprx-vision&pbk=${public_key}&packetEncoding=xudp&sid=${sid}#${remark}"
    echo "# UserGuest${counter}"
    counter=$((counter + 1))
    echo -e "\e[36m$link\e[0m\n"
done

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

### Счетчик запуска скрипта
runs_func(){
  # Count script runs using hits.seeyoufarm.com
  if ! mktemp -u --suffix=RRC &>/dev/null; then
      count_file=$(mktemp)
  else
      count_file=$(mktemp --suffix=RRC)
  fi

  max_retries=4
  retry_count=0
  total_runs="smth_went_wrong_lol"

  while [[ $retry_count -lt $max_retries ]]; do
    if [[ $retry_count -eq 0 ]]; then
        timeout=10  # Первая попытка с max-time 10
    else
        timeout=5   # Остальные попытки с max-time 5
    fi

    if curl -s --max-time "$timeout" "https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fraw.githubusercontent.com%2Faiovin%2Flazy-vpn%2Frefs%2Fheads%2Fmain%2Fsetup.sh&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=false" > "$count_file" 2>/dev/null; then
        total_runs=$(tail -3 "$count_file" | head -n 1 | awk '{print $7}')
        break
    fi

    retry_count=$((retry_count + 1))

    if [[ $retry_count -lt $max_retries ]]; then
        echo "API hits.seeyoufarm.com недоступен. Жду 5 секунд. Попытка $retry_count/3"
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
    echo
  fi
}

echo -e "\e[0;32mНастройка конфига окончена.\e[0m Завершаю работу скрипта.."
runs_func
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
for sensitive_var in priv_and_pub_keys private_key public_key sid; do
  eval "$sensitive_var=\$(head -c 100 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')"
  unset "$sensitive_var"
done

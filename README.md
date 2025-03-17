# lazy vpn
Bash скрипт для автоматической настройки vpn `vless reality` на базе xray core.<br><br>
Запустить и следовать инструкциям:
```
sudo bash -c "$(curl -Ls https://raw.githubusercontent.com/aiovin/lazy-vpn/refs/heads/main/setup.sh)"
```
Протестировано на Ubuntu 24.04 и Debian 12.

### Что умеет:
- Полная установка: Установка и настройка веб сервера Caddy (для steal from yourself), установка xray core, создание конфига и ссылок на подключение. Требуется уже созданная DNS запись на ip сервера.
- Настройка конфига используя уже существующий собственный веб сервер, нужно только указать порт на котором он работает и ваш домен.
- Базовая настройка: Установка xray core (опционально) и настройка vless reality конфига с чужим sni. Свой домен не требуется, но вы должны заранее самостоятельно выбрать sni.

### Особенности:
- Конфиг xray в скрипте не предолагает ни warp ни какую либо еще маршрутизацию.
- Правил в конфиге два: заблокированы торренты и заблокирован трафик на ру сайты.
- Обязательные зависимости которые будут установлены автоматически при первом запуске: dig, openssl, jq. Установка остального (xray, caddy, uwf) опциональна.

---

<p align="center">
  <img src="https://raw.githubusercontent.com/aiovin/lazy-vpn/refs/heads/main/example.png" width="75%">
  <br><i>Пример настройки только конфига</i>
</p>



## Оцените другой мой lazy скрипт.
Легкая конфигурация свежено vps:
[https://github.com/aiovin/lazy-vps](https://github.com/aiovin/lazy-vps?tab=readme-ov-file#lazy-vps-setup-rus)

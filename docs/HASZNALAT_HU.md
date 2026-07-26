# Monitorozo használati kézikönyv

## Belépés

Nyisd meg:

```text
https://monitor.acuwall.hu/
```

Az admin jelszó az, amelyből a telepítéskor a `monitorozo-server hash-password`
paranccsal készült a hash.

## Főoldal

A dashboard a beérkező agent jelentésekből mutatja a szerver állapotát.

Fontos mezők:

- **Szerverek**: minden bejelentkezett agent külön kártyán jelenik meg.
- **Elérhető / nem elérhető**: az utolsó jelentés ideje alapján számolt állapot.
- **CPU**: aktuális processzorhasználat százalékban.
- **RAM**: aktuális memóriahasználat százalékban.
- **Cserehely**: swap használat.
- **Üzemidő**: a figyelt szerver uptime értéke.
- **Fájlrendszerek**: mountpointonkénti lemezhasználat.
- **Lemez I/O**: olvasási és írási sebesség.
- **Hálózat**: RX/TX forgalom interfészenként.

## Előzmények

A CPU / RAM előzmény grafikon időtartama választható:

- 1 óra
- 24 óra
- 7 nap
- 30 nap
- 90 nap

A nyers adatok alapból 7 napig, az órás aggregátumok 90 napig maradnak meg.

## Riasztások

Az **Aktív riasztások** szekció csak azokat a riasztásokat mutatja, amelyek még
nincsenek nyugtázva.

Tipikus riasztások:

- magas CPU használat
- magas memóriahasználat
- magas vagy kritikus lemezhasználat
- agent nem elérhető
- systemd szolgáltatás nem elérhető
- Docker konténer leállt vagy hibás
- HTTP ellenőrzés sikertelen
- TLS tanúsítvány hamarosan lejár

## Nyugtázás

Ha egy riasztásról tudsz, kattints a **Nyugtázás** gombra.

Nyugtázás után:

- a riasztás eltűnik az Aktív riasztások listából;
- az adatbázisban megmarad nyugtázottként;
- ha a probléma később ténylegesen megszűnik, a rendszer megoldottnak zárja;
- ha ugyanaz a probléma újra külön eseményként jelentkezik, újra megjelenhet.

Ez azért hasznos, mert a dashboardon csak az új vagy még nem kezelt problémák
maradnak szem előtt.

## Riasztási előzmények

A **Riasztási előzmények** a megoldott riasztásokat mutatja. Itt látszik:

- melyik agent érintett;
- milyen szabály miatt jött létre a riasztás;
- mikor indult;
- mikor oldódott meg.

## Agent ellenőrzése

Production szerveren:

```bash
sudo systemctl status monitorozo-agent --no-pager
sudo journalctl -u monitorozo-agent --since "10 minutes ago" --no-pager
```

Ha `401` vagy `403` hiba látszik, akkor a token vagy az `agent_id` nem egyezik a
monitoring szerver konfigurációjával.

## Server ellenőrzése

Monitoring szerveren:

```bash
sudo systemctl status monitorozo-server --no-pager
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
sudo journalctl -u monitorozo-server --since "10 minutes ago" --no-pager
```

Nginx ellenőrzés:

```bash
sudo nginx -t
curl -I https://monitor.acuwall.hu/
```

## Gyakori hibák

**Nem jelenik meg az agent**

Ellenőrizd:

```bash
sudo journalctl -u monitorozo-agent --since "10 minutes ago" --no-pager
```

Leggyakoribb ok: rossz token, rossz `agent_id`, HTTPS vagy tűzfal hiba.

**Belépés után too many login attempts**

Túl sok sikertelen belépési próbálkozás volt. Várj pár percet, vagy restartold:

```bash
sudo systemctl restart monitorozo-server
```

**HTTPS timeout**

Ellenőrizd a Lightsail firewallt:

```text
TCP 443 legyen nyitva
TCP 80 legyen nyitva a tanúsítvány megújításhoz
```

**Tanúsítvány hiba**

Ellenőrizd:

```bash
sudo certbot renew --dry-run
sudo nginx -t
```

## Biztonsági javaslatok

- A `8080` portot ne nyisd ki publikusan.
- Az agent tokent ne commitold Gitbe.
- Az `/etc/monitorozo/*.env` fájlok legyenek `0640` módban.
- A Docker check csak akkor legyen bekapcsolva, ha tényleg kell.
- A `docker.sock` elérés root-szintű jogosultságot jelent.
- SSH csak saját IP-ről vagy VPN-ről legyen nyitva.

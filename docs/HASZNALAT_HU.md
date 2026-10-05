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

- **Szerverek**: a konfigurált agentek is látszanak, akkor is, ha még nincs mérésük.
- **Kapcsolat és mérés**: az utolsó kapcsolat és a mérés frissessége külön állapot.
  A kapcsolódó agent küldhet régi, korábban sorba állított adatokat is.
- **CPU**: aktuális processzorhasználat százalékban.
- **RAM**: aktuális memóriahasználat százalékban.
- **Cserehely**: swap használat a lenyitható részletekben, ha van swap.
- **Üzemidő**: a figyelt szerver uptime értéke.
- **Tárhelyhasználat**: szerveroldali csatolási útvonal, eszköz, foglaltság,
  szabad hely és változás az előző méréshez képest, a két mérés közti idővel.
  Összehasonlítás csak azonos útvonal, eszköz és teljes kapacitás esetén történik.
  Ez teljes fájlrendszert mér, nem almappákat. A lemezriasztás megadja a
  megfelelő `df` és `du` ellenőrzés útvonalát is.
- **Lemez I/O és hálózat**: a lenyitható részletekben; az írási sebesség
  nem azonos a tárhely foglaltságának növekedésével.

A mérések oldalújratöltés nélkül frissülnek. A lenyitott részletek, a grafikon
időtartama és az email-űrlap megmaradnak. A rendszer 15 másodpercenként is
ellenőrzi az állapotot, így az offline állapot élő esemény nélkül is megjelenik.
Frissítési hiba esetén az utolsó adatok maradnak láthatók, hibaüzenettel.

## Előzmények

A CPU / RAM előzmény grafikon időtartama választható:

- 1 óra
- 24 óra
- 7 nap
- 30 nap
- 90 nap

A nyers adatok alapból 7 napig, az órás aggregátumok 90 napig maradnak meg.

## Riasztások

A **Beavatkozásra vár** szekció a fennálló riasztásokat mutatja, elöl a kritikus
hibákkal. Minden riasztás tartalmazza a mért értéket, a küszöböt, az érintett
szervert és erőforrást, valamint az ellenőrzéshez javasolt teendőt.

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

- a riasztás látható marad, „Nyugtázva · a hiba még fennáll” jelöléssel;
- az adatbázisban megmarad nyugtázottként;
- ha a probléma később ténylegesen megszűnik, a rendszer megoldottnak zárja;
- ha ugyanaz a probléma újra külön eseményként jelentkezik, újra megjelenhet.

A nyugtázás nem javítja meg a hibát, ezért nem jelöl egészségesnek egy továbbra
is hibás erőforrást.

## Email-értesítések

Belépés után nyisd meg az **Email-értesítések** fület. Add meg a címzettet,
kapcsold be a küldést, majd ments. Alapértelmezésben a kritikus riasztások és
a helyreállások küldhetők; a figyelmeztetések külön kapcsolhatók.
A beállítások az SQLite-adatbázisban maradnak, újraindítás után is érvényesek,
és nem függenek attól, hogy be vagy-e jelentkezve.

A **Teszt email küldése** az űrlapon szereplő címre küld, mentés nélkül.
A siker azt jelenti, hogy az SMTP-kiszolgáló elfogadta a levelet; a címzett
postaládáját és spam mappáját is ellenőrizni kell. Percenként legfeljebb három
teszt küldhető. Hibánál a felület jelzi, melyik beállítást kell ellenőrizni.

Az SMTP-kapcsolatot továbbra is a szerveren kell megadni a `server.yaml`
`smtp` részében: `enabled`, `address` (STARTTLS, jellemzően 587-es port),
`from`, `username`, és kezdeti `to`. A jelszó a `MONITOROZO_SMTP_PASSWORD`
környezeti változóval adható meg. Ezután indítsd újra a szervert.
A felületen mentett címzett felülírja a YAML `to` értékét.
Az SMTP-jelszó nem kerül a böngészőbe vagy az értesítési beállítások táblájába.

A kikapcsolt vagy kiszűrt értesítéseket a rendszer elnyomottként rögzíti,
nem sikeresen elküldöttként. A későbbi bekapcsolás nem küldi újra ezeket.
A valódi küldési hibák a meglévő háttérfolyamatban újrapróbálhatók.

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

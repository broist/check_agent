package alerts

import (
	"fmt"
	"strings"

	"github.com/broist/check_agent/internal/model"
	"github.com/broist/check_agent/internal/storage"
)

type Description struct{ Title, Measurement, Action string }

// Display context comes from the latest report; the stored rule identity stays stable.
func WithReport(a storage.Alert, report model.Report) storage.Alert {
	a.Hostname = report.Hostname
	a.Target = a.Resource
	if a.RuleKey == "http_failed" || a.RuleKey == "tls_expiring" {
		for _, check := range report.HTTPChecks {
			if check.Name == a.Resource {
				a.Target = check.URL
				break
			}
		}
	}
	return a
}

func Describe(a storage.Alert) Description {
	if a.Target == "" {
		a.Target = a.Resource
	}
	percent := fmt.Sprintf("Mért érték: %.1f%% · küszöb: %.1f%%", a.Value, a.Threshold)
	switch a.RuleKey {
	case "cpu_high":
		return Description{"Tartósan magas CPU-terhelés", percent, "A megjelölt szerveren a top paranccsal azonosítsd a legtöbb CPU-t használó folyamatot. Ellenőrizd a terhelést és a folyamat naplóját."}
	case "memory_high":
		return Description{"Kevés szabad memória", percent, "A megjelölt szerveren ellenőrizd a free -h kimenetét, majd a top memória szerinti listáját. Vizsgáld meg a legnagyobb folyamatot és a memóriakorlátait."}
	case "disk_warning", "disk_critical", "disk":
		path := "'" + strings.ReplaceAll(a.Resource, "'", "'\"'\"'") + "'"
		return Description{"Megtelt vagy telítődő tárhely", percent, "Érintett csatolási útvonal: " + a.Resource + ". Ellenőrzés: df -h -- " + path + ". A nagy könyvtárak kereséséhez: sudo du -xhd1 -- " + path + ". A mérés a teljes fájlrendszerre vonatkozik; az érintett almappát ez az ellenőrzés azonosítja. Ellenőrizd a naplómegőrzést vagy bővítsd a tárhelyet."}
	case "agent_offline":
		return Description{"Nem érkezik adat a szerverről", fmt.Sprintf("Utolsó kapcsolat óta: %.0f másodperc · határ: %.0f másodperc", a.Value, a.Threshold), "Ellenőrizd, hogy a szerver elérhető-e. A szerveren futtasd: systemctl status monitorozo-agent és journalctl -u monitorozo-agent -n 50. Ellenőrizd az agent hálózati kapcsolatát a monitorozó szerverhez."}
	case "systemd_unavailable":
		return Description{"A szolgáltatás nem fut", "Szolgáltatás: " + a.Resource, "Ellenőrizd a megjelölt systemd egység állapotát és naplóját a systemctl status és journalctl -u parancsokkal. Újraindítás előtt keresd meg a leállás okát."}
	case "docker_stopped", "docker_unhealthy":
		return Description{"A konténer nem működik megfelelően", "Konténer: " + a.Resource, "Ellenőrizd a megjelölt konténert a docker inspect és docker logs parancsokkal, különösen a kilépési kódot és a healthcheck eredményét."}
	case "http_failed":
		return Description{"A webes végpont ellenőrzése sikertelen", fmt.Sprintf("Ellenőrzés: %s · HTTP-kód: %.0f (0: nem érkezett válasz)", a.Target, a.Value), "Ellenőrizd az érintett URL elérhetőségét a szerverről, az alkalmazás és a reverse proxy naplóit, valamint a DNS- és TLS-beállításokat."}
	case "tls_expiring":
		return Description{"A TLS-tanúsítvány hamarosan lejár", fmt.Sprintf("Hátralévő idő: %.1f nap · figyelmeztetési határ: %.1f nap", a.Value, a.Threshold), "Újítsd meg az érintett végpont tanúsítványát. Ellenőrizd az automatikus megújítás naplóját, majd a kiszolgált tanúsítvány lejárati dátumát."}
	case "test_email":
		return Description{"Tesztértesítés", "Az SMTP-kiszolgáló elfogadta a tesztüzenetet.", "Nincs szükség beavatkozásra. Ez a Monitorozo email-beállításainak tesztje."}
	default:
		return Description{a.RuleKey, fmt.Sprintf("Mért érték: %.2f · küszöb: %.2f", a.Value, a.Threshold), "Ellenőrizd a megjelölt erőforrás állapotát és naplóit a szerveren."}
	}
}

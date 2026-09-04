package httpapi

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/n4darae/huawei-API/src/internal/store"
)

const (
	FormatTXT    = "txt"
	FormatCSV    = "csv"
	SchemeSocks5 = "socks5"
	SchemeHTTP   = "http"

	CSVHeader = "host,port,username,password"
)

type ExportRow struct {
	ID       string
	Host     string
	Port     int
	Username string
	Password string
}

type ExportSkip struct {
	ID     string
	Reason string
}

func exportPort(p Proxy, scheme string) int {
	if scheme == SchemeHTTP {
		return p.HTTPPort
	}
	return p.SocksPort
}

func usesUserPass(mode string) bool { return mode == "userpass" || mode == "both" }

func BuildExport(proxies []Proxy, scheme, format string) (string, []ExportRow, []ExportSkip) {
	rows := []ExportRow{}
	skipped := []ExportSkip{}

	for _, p := range proxies {
		port := exportPort(p, scheme)
		if port == 0 {
			skipped = append(skipped, ExportSkip{ID: p.ID, Reason: "no " + scheme + " port"})
			continue
		}
		if !usesUserPass(p.AuthMode) {
			rows = append(rows, ExportRow{ID: p.ID, Host: p.Host, Port: port})
			continue
		}
		if p.Password == "" {
			skipped = append(skipped, ExportSkip{ID: p.ID, Reason: "password not returned by the API"})
			continue
		}
		rows = append(rows, ExportRow{ID: p.ID, Host: p.Host, Port: port, Username: p.Username, Password: p.Password})
	}

	lines := make([]string, 0, len(rows)+1)
	if format == FormatCSV {
		lines = append(lines, CSVHeader)
		for _, r := range rows {
			lines = append(lines, strings.Join([]string{
				csvCell(r.Host), csvCell(strconv.Itoa(r.Port)), csvCell(r.Username), csvCell(r.Password),
			}, ","))
		}
		return strings.Join(lines, "\n"), rows, skipped
	}

	for _, r := range rows {
		if r.Username == "" {
			lines = append(lines, r.Host+":"+strconv.Itoa(r.Port))
			continue
		}
		lines = append(lines, r.Host+":"+strconv.Itoa(r.Port)+":"+r.Username+":"+r.Password)
	}
	return strings.Join(lines, "\n"), rows, skipped
}

var csvNeedsQuote = regexp.MustCompile(`[",\n]`)

const csvFormulaLeaders = "=+-@\t\r"

func csvCell(v string) string {
	if v != "" && strings.ContainsAny(v[:1], csvFormulaLeaders) {
		v = "'" + v
	}
	if !csvNeedsQuote.MatchString(v) {
		return v
	}
	return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
}

func (a *API) exportProxies(w http.ResponseWriter, r *http.Request) {
	format := FormatTXT
	if strings.EqualFold(r.URL.Query().Get("format"), FormatCSV) {
		format = FormatCSV
	}
	scheme := SchemeSocks5
	if strings.EqualFold(r.URL.Query().Get("scheme"), SchemeHTTP) {
		scheme = SchemeHTTP
	}

	var wanted map[string]bool
	if raw := strings.TrimSpace(r.URL.Query().Get("ids")); raw != "" {
		wanted = map[string]bool{}
		for _, id := range strings.Split(raw, ",") {
			if id = strings.TrimSpace(id); id != "" {
				wanted[id] = true
			}
		}
	}

	views, err := a.buildProxies(r.Context(), store.ProxyFilter{})
	if err != nil {
		writeError(w, r, translate(err))
		return
	}
	list := make([]Proxy, 0, len(views))
	for _, v := range views {
		if wanted != nil && !wanted[v.dto.ID] {
			continue
		}
		list = append(list, v.dto)
	}

	body, rows, skipped := BuildExport(list, scheme, format)

	contentType := "text/plain; charset=utf-8"
	filename := "proxies.txt"
	if format == FormatCSV {
		contentType = "text/csv; charset=utf-8"
		filename = "proxies.csv"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("X-Export-Rows", strconv.Itoa(len(rows)))
	w.Header().Set("X-Export-Skipped", strconv.Itoa(len(skipped)))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(body)); err != nil {
		return
	}
}

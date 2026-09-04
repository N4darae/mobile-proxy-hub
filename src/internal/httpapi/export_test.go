package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/n4darae/huawei-API/src/internal/domain"
)

func TestExportTxtIsHostPortUserPassOnePerLine(t *testing.T) {
	h := newHarness(t)
	h.login()

	res := h.do(http.MethodGet, APIBase+"/proxies/export?format=txt&scheme=socks5", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("returned %d: %s", res.StatusCode, res.text())
	}
	if ct := res.Header.Get("Content-Type"); !contains(ct, "text/plain") {
		t.Fatalf("content type is %q", ct)
	}

	lines := strings.Split(res.text(), "\n")
	if lines[0] != "203.0.113.10:21001:cust_px01:Kq7mZr2xTn9wLb4V" {
		t.Fatalf("first line is %q", lines[0])
	}
	if strings.HasSuffix(res.text(), "\n") {
		t.Fatal("the body must not end in a newline; the SPA joins with \\n")
	}
}

func TestExportSwitchesToTheHTTPPortWithoutTouchingCredentials(t *testing.T) {
	h := newHarness(t)
	h.login()

	res := h.do(http.MethodGet, APIBase+"/proxies/export?format=txt&scheme=http", nil)
	lines := strings.Split(res.text(), "\n")
	if lines[0] != "203.0.113.10:22001:cust_px01:Kq7mZr2xTn9wLb4V" {
		t.Fatalf("first line is %q", lines[0])
	}
}

func TestExportEmitsHostPortOnlyForAnIPWhitelistedProxy(t *testing.T) {
	h := newHarness(t)
	h.login()

	res := h.do(http.MethodGet, APIBase+"/proxies/export?format=txt", nil)
	if !contains(res.text(), "203.0.113.10:21002\n") && !strings.HasSuffix(res.text(), "203.0.113.10:21002") {
		t.Fatalf("an iplist proxy must export as host:port with no credentials, body is:\n%s", res.text())
	}
	if contains(res.text(), "21002:cust_px02") {
		t.Fatal("an iplist proxy leaked credentials into the export")
	}
}

func TestExportLeavesOutAUserpassProxyWithNoPassword(t *testing.T) {
	h := newHarness(t)
	h.login()

	if err := h.store.Proxies().SetCredentials(context.Background(), "px01", "cust_px01", ""); err != nil {
		t.Fatalf("clear password: %v", err)
	}

	res := h.do(http.MethodGet, APIBase+"/proxies/export?format=txt", nil)
	if contains(res.text(), ":21001") {
		t.Fatalf("a credentialled proxy with no password must be left out, body is:\n%s", res.text())
	}
	if res.Header.Get("X-Export-Skipped") != "1" {
		t.Fatalf("X-Export-Skipped is %q, want 1", res.Header.Get("X-Export-Skipped"))
	}
}

func TestExportCsvHasAHeaderRowAndTheSameFourFields(t *testing.T) {
	h := newHarness(t)
	h.login()

	res := h.do(http.MethodGet, APIBase+"/proxies/export?format=csv", nil)
	if ct := res.Header.Get("Content-Type"); !contains(ct, "text/csv") {
		t.Fatalf("content type is %q", ct)
	}
	lines := strings.Split(res.text(), "\n")
	if lines[0] != CSVHeader {
		t.Fatalf("header row is %q, want %q", lines[0], CSVHeader)
	}
	if lines[1] != "203.0.113.10,21001,cust_px01,Kq7mZr2xTn9wLb4V" {
		t.Fatalf("first data row is %q", lines[1])
	}
}

func TestExportCsvLeavesTwoEmptyFieldsForAnIPWhitelistedProxy(t *testing.T) {
	h := newHarness(t)
	h.login()

	res := h.do(http.MethodGet, APIBase+"/proxies/export?format=csv", nil)
	if !contains(res.text(), "203.0.113.10,21002,,") {
		t.Fatalf("body is:\n%s", res.text())
	}
}

func TestExportHonoursTheIdsFilter(t *testing.T) {
	h := newHarness(t)
	h.login()

	res := h.do(http.MethodGet, APIBase+"/proxies/export?format=txt&ids=px01", nil)
	lines := strings.Split(res.text(), "\n")
	if len(lines) != 1 || !contains(lines[0], ":21001:") {
		t.Fatalf("ids filter returned:\n%s", res.text())
	}
	if res.Header.Get("X-Export-Rows") != "1" {
		t.Fatalf("X-Export-Rows is %q", res.Header.Get("X-Export-Rows"))
	}
}

func TestExportDefaultsToTxtAndSocks5(t *testing.T) {
	h := newHarness(t)
	h.login()

	res := h.do(http.MethodGet, APIBase+"/proxies/export", nil)
	if !contains(res.text(), ":21001:") {
		t.Fatalf("default scheme is not socks5:\n%s", res.text())
	}
	if ct := res.Header.Get("Content-Type"); !contains(ct, "text/plain") {
		t.Fatalf("default format is not txt: %q", ct)
	}
}

func TestExportSendsAFilename(t *testing.T) {
	h := newHarness(t)
	h.login()

	txt := h.do(http.MethodGet, APIBase+"/proxies/export?format=txt", nil)
	if !contains(txt.Header.Get("Content-Disposition"), "proxies.txt") {
		t.Fatalf("disposition is %q", txt.Header.Get("Content-Disposition"))
	}
	csv := h.do(http.MethodGet, APIBase+"/proxies/export?format=csv", nil)
	if !contains(csv.Header.Get("Content-Disposition"), "proxies.csv") {
		t.Fatalf("disposition is %q", csv.Header.Get("Content-Disposition"))
	}
}

func TestExportQuotesCsvCellsThatNeedIt(t *testing.T) {
	rows := []Proxy{{
		ID: "px01", Host: "203.0.113.10", SocksPort: 21001,
		Username: `od"d`, Password: "a,b", AuthMode: string(domain.AuthUserPass),
	}}
	body, _, _ := BuildExport(rows, SchemeSocks5, FormatCSV)
	want := "host,port,username,password\n203.0.113.10,21001,\"od\"\"d\",\"a,b\""
	if body != want {
		t.Fatalf("csv is %q, want %q", body, want)
	}
}

func TestExportSkipsAProxyWithNoPortForTheScheme(t *testing.T) {
	rows := []Proxy{{ID: "px01", Host: "203.0.113.10", SocksPort: 21001, AuthMode: string(domain.AuthIPList)}}
	body, emitted, skipped := BuildExport(rows, SchemeHTTP, FormatTXT)
	if body != "" || len(emitted) != 0 {
		t.Fatalf("body is %q", body)
	}
	if len(skipped) != 1 || skipped[0].Reason != "no http port" {
		t.Fatalf("skipped is %+v", skipped)
	}
}

func TestExportNeedsASession(t *testing.T) {
	h := newHarness(t)
	if res := h.do(http.MethodGet, APIBase+"/proxies/export", nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("returned %d", res.StatusCode)
	}
}

func TestCsvCellDefusesSpreadsheetFormulas(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"=1+1", "'=1+1"},
		{"+SUM(A1)", "'+SUM(A1)"},
		{"-2", "'-2"},
		{"@echo", "'@echo"},
		{"\tlead", "'\tlead"},
		{"=HYPERLINK(\"http://x\",\"y\")", "\"'=HYPERLINK(\"\"http://x\"\",\"\"y\"\")\""},
		{"cust_1", "cust_1"},
		{"", ""},
		{"a=b", "a=b"},
		{"has,comma", "\"has,comma\""},
	} {
		if got := csvCell(tc.in); got != tc.want {
			t.Errorf("csvCell(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

package bhosted

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/libdns/libdns"
)

// fake mimics the response shapes tailmirror handles; bHosted's exact
// schema is unverified.
type fake struct {
	mu      sync.Mutex
	next    int
	records map[string][4]string
	flaky   bool
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r.ParseForm()

	if r.Form.Get("user") != "u" || r.Form.Get("password") != "p" {
		fmt.Fprint(w, `<response><done>false</done><errors>1</errors><err1>Bad login</err1></response>`)
		return
	}
	if r.Form.Get("sld") != "example" || r.Form.Get("tld") != "nl" {
		fmt.Fprint(w, `<response><done>false</done><errors>1</errors><err1>Unknown domain</err1></response>`)
		return
	}

	switch strings.TrimPrefix(r.URL.Path, "/") {
	case "getrecords":
		var b strings.Builder
		b.WriteString(`<response><done>true</done><errors>0</errors><records>`)
		for id, rec := range f.records {
			fmt.Fprintf(&b, `<record><id>%s</id><type>%s</type><name>%s</name><content>%s</content><ttl>%s</ttl></record>`,
				id, rec[0], rec[1], rec[2], rec[3])
		}
		b.WriteString(`</records></response>`)
		fmt.Fprint(w, b.String())

	case "addrecord":
		f.next++
		content := r.Form.Get("content")
		if r.Form.Get("type") == "TXT" {
			content = `"` + content + `"`
		}
		name := r.Form.Get("name") + ".example.nl"
		if r.Form.Get("name") == "@" {
			name = "example.nl"
		}
		f.records[strconv.Itoa(f.next)] = [4]string{r.Form.Get("type"), name, content, r.Form.Get("ttl")}
		if f.flaky {
			fmt.Fprint(w, `<response><done>false</done><errors>1</errors><err1>Newly created record not found</err1></response>`)
			return
		}
		fmt.Fprint(w, `<response><done>true</done><errors>0</errors></response>`)

	case "delrecord":
		delete(f.records, r.Form.Get("id"))
		fmt.Fprint(w, `<response><done>true</done><errors>0</errors></response>`)
	}
}

func setup(t *testing.T, f *fake) *Provider {
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	old := endpoint
	endpoint = srv.URL
	t.Cleanup(func() { endpoint = old })
	return &Provider{Username: "u", Password: "p"}
}

func txt(name, text string) libdns.Record {
	return libdns.TXT{Name: name, Text: text}
}

func TestChallengeLifecycle(t *testing.T) {
	f := &fake{records: map[string][4]string{"keep": {"A", "nov.example.nl", "100.64.0.1", "3600"}}}
	p := setup(t, f)
	ctx := context.Background()

	if _, err := p.AppendRecords(ctx, "example.nl.", []libdns.Record{txt("_acme-challenge.www", "node-a")}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.AppendRecords(ctx, "example.nl.", []libdns.Record{txt("_acme-challenge.www", "node-b")}); err != nil {
		t.Fatal(err)
	}

	deleted, err := p.DeleteRecords(ctx, "example.nl.", []libdns.Record{txt("_acme-challenge.www", "node-a")})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0].(libdns.TXT).Text != "node-a" {
		t.Fatalf("deleted %v, want node-a only", deleted)
	}

	recs, err := p.GetRecords(ctx, "example.nl.")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range recs {
		rr := r.RR()
		got = append(got, rr.Name+" "+rr.Type+" "+rr.Data)
	}
	if len(got) != 2 || !contains(got, "_acme-challenge.www TXT node-b") || !contains(got, "nov A 100.64.0.1") {
		t.Fatalf("records %v", got)
	}
}

func TestSetRecords(t *testing.T) {
	f := &fake{records: map[string][4]string{
		"1": {"A", "example.nl", "192.0.2.1", "3600"},
		"2": {"A", "example.nl", "192.0.2.2", "3600"},
		"3": {"TXT", "example.nl", `"hello world"`, "3600"},
	}}
	p := setup(t, f)
	ctx := context.Background()

	set := libdns.Address{Name: "@", IP: netip.MustParseAddr("192.0.2.3")}
	if _, err := p.SetRecords(ctx, "example.nl.", []libdns.Record{set}); err != nil {
		t.Fatal(err)
	}

	recs, err := p.GetRecords(ctx, "example.nl.")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range recs {
		rr := r.RR()
		got = append(got, rr.Name+" "+rr.Type+" "+rr.Data)
	}
	if len(got) != 2 || !contains(got, "@ A 192.0.2.3") || !contains(got, "@ TXT hello world") {
		t.Fatalf("records %v", got)
	}
}

func TestFlakyAdd(t *testing.T) {
	f := &fake{records: map[string][4]string{}, flaky: true}
	p := setup(t, f)

	if _, err := p.AppendRecords(context.Background(), "example.nl.", []libdns.Record{txt("_acme-challenge", "x")}); err != nil {
		t.Fatalf("created record reported as failure: %v", err)
	}
}

func TestErrors(t *testing.T) {
	p := setup(t, &fake{records: map[string][4]string{}})
	p.Password = "wrong"

	_, err := p.GetRecords(context.Background(), "example.nl.")
	if err == nil || !strings.Contains(err.Error(), "Bad login") {
		t.Fatalf("got %v, want bad login", err)
	}

	if _, err := p.GetRecords(context.Background(), "localhost."); err == nil {
		t.Fatal("accepted zone without a TLD")
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

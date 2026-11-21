package bhosted

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

var endpoint = "https://webservices.bhosted.com/dns"

// record is a record as bHosted's API returns it.
type record struct {
	id      string
	kind    string
	name    string
	content string
	ttl     time.Duration
}

// node is a generic XML element; bHosted's response schema is not
// documented, so responses are searched by element name.
type node struct {
	XMLName xml.Name
	Text    string `xml:",chardata"`
	Nodes   []node `xml:",any"`
}

func (n *node) walk(f func(*node)) {
	f(n)
	for i := range n.Nodes {
		n.Nodes[i].walk(f)
	}
}

func (n *node) name() string {
	return strings.ToLower(n.XMLName.Local)
}

func (n *node) text() string {
	return strings.TrimSpace(n.Text)
}

func splitZone(zone string) (sld, tld string, err error) {
	sld, tld, ok := strings.Cut(strings.TrimSuffix(zone, "."), ".")
	if !ok || sld == "" || tld == "" {
		return "", "", fmt.Errorf("invalid zone %q", zone)
	}
	return sld, tld, nil
}

func responseError(root *node) error {
	values := map[string]string{}
	root.walk(func(n *node) { values[n.name()] = n.text() })

	errs, hasErrs := values["errors"]
	done, hasDone := values["done"]
	if (!hasErrs || errs == "0") && (!hasDone || strings.EqualFold(done, "true")) {
		return nil
	}

	var messages []string
	root.walk(func(n *node) {
		if strings.HasPrefix(n.name(), "err") && n.text() != "" {
			messages = append(messages, n.text())
		}
	})
	if len(messages) == 0 {
		return fmt.Errorf("unknown error")
	}
	return fmt.Errorf("%s", strings.Join(messages, "; "))
}

func (p *Provider) request(ctx context.Context, command, zone string, values url.Values) (*node, error) {
	sld, tld, err := splitZone(zone)
	if err != nil {
		return nil, err
	}

	form := url.Values{
		"user":     {p.Username},
		"password": {p.Password},
		"sld":      {sld},
		"tld":      {tld},
	}
	for k, v := range values {
		form[k] = v
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/"+command, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", command, err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: unexpected status %s", command, res.Status)
	}

	var root node
	if err := xml.NewDecoder(res.Body).Decode(&root); err != nil {
		return nil, fmt.Errorf("%s: invalid response: %w", command, err)
	}
	if err := responseError(&root); err != nil {
		return nil, fmt.Errorf("%s: %w", command, err)
	}
	return &root, nil
}

func first(fields map[string]string, keys ...string) (string, bool) {
	for _, k := range keys {
		if v, ok := fields[k]; ok {
			return v, true
		}
	}
	return "", false
}

// relativeName accepts both relative and fully-qualified names, since
// bHosted's choice between them is undocumented.
func relativeName(name, zone string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")

	switch {
	case name == "" || name == "@" || name == zone:
		return "@"
	case strings.HasSuffix(name, "."+zone):
		return strings.TrimSuffix(name, "."+zone)
	}
	return name
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func (p *Provider) getRecords(ctx context.Context, zone string) ([]record, error) {
	root, err := p.request(ctx, "getrecords", zone, nil)
	if err != nil {
		return nil, err
	}

	var records []record
	hasRecordElements := false

	root.walk(func(n *node) {
		if strings.HasPrefix(n.name(), "record") {
			hasRecordElements = true
		}

		fields := map[string]string{}
		for i := range n.Nodes {
			if c := &n.Nodes[i]; len(c.Nodes) == 0 {
				fields[c.name()] = c.text()
			}
		}

		id, _ := first(fields, "id", "recordid")
		kind, _ := first(fields, "type", "recordtype")
		name, hasName := first(fields, "name", "host")
		content, hasContent := first(fields, "content", "value", "data")
		if id == "" || kind == "" || !hasName || !hasContent {
			return
		}

		kind = strings.ToUpper(kind)
		if kind == "TXT" {
			content = unquote(content)
		}

		ttl, _ := strconv.Atoi(fields["ttl"])

		records = append(records, record{
			id:      id,
			kind:    kind,
			name:    relativeName(name, zone),
			content: content,
			ttl:     time.Duration(ttl) * time.Second,
		})
	})

	if len(records) == 0 && hasRecordElements {
		return nil, fmt.Errorf("getrecords: unrecognized response")
	}
	return records, nil
}

func (p *Provider) addRecord(ctx context.Context, zone string, rr libdns.RR) error {
	_, err := p.request(ctx, "addrecord", zone, url.Values{
		"type":    {rr.Type},
		"name":    {rr.Name},
		"content": {rr.Data},
		"ttl":     {strconv.Itoa(int(rr.TTL.Seconds()))},
	})

	// bHosted sometimes reports this although the record was created.
	if err != nil && strings.Contains(err.Error(), "Newly created record not found") {
		records, gerr := p.getRecords(ctx, zone)
		if gerr != nil {
			return err
		}
		for _, r := range records {
			if r.matches(rr, zone) {
				return nil
			}
		}
	}
	return err
}

func (p *Provider) deleteRecord(ctx context.Context, zone string, r record) error {
	_, err := p.request(ctx, "delrecord", zone, url.Values{"id": {r.id}})
	return err
}

// matches ignores TTL: bHosted may rewrite it, and an unmatched TXT record
// would leave ACME challenges behind.
func (r record) matches(rr libdns.RR, zone string) bool {
	return r.name == relativeName(rr.Name, zone) &&
		(rr.Type == "" || strings.EqualFold(r.kind, rr.Type)) &&
		(rr.Data == "" || r.content == rr.Data)
}

func (r record) libdnsRecord() (libdns.Record, error) {
	return libdns.RR{Name: r.name, TTL: r.ttl, Type: r.kind, Data: r.content}.Parse()
}

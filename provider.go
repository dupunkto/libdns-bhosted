// Package bhosted implements a DNS record management client compatible with
// the libdns interfaces for [bHosted].
//
// # Updates are not atomic
//
// bHosted's API adds and deletes one record per call and has no
// transactions. SetRecords therefore deletes and adds records one by one; if
// it fails halfway, the zone is left partially updated.
//
// Writes are serialized within one process. Multiple processes can safely add
// and delete records of the same name, since records are deleted by ID rather
// than by name.
//
// # TTL
//
// Records without a TTL are created with a TTL of one hour. DeleteRecords
// ignores the TTL when matching records.
//
// [bHosted]: https://www.bhosted.nl
package bhosted

import (
	"context"
	"time"

	"github.com/libdns/libdns"
)

const defaultTTL = time.Hour

// writeToken serializes writes; it is a channel rather than a mutex so
// waiting for it honours context cancellation.
var writeToken = make(chan struct{}, 1)

func init() {
	writeToken <- struct{}{}
}

func acquireWriteToken(ctx context.Context) error {
	select {
	case <-writeToken:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseWriteToken() {
	writeToken <- struct{}{}
}

// Provider facilitates DNS record manipulation with bHosted.
type Provider struct {
	// Username is the bHosted account name.
	Username string `json:"username,omitempty"`

	// Password is the bHosted account password.
	Password string `json:"password,omitempty"`
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	records, err := p.getRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	out := make([]libdns.Record, 0, len(records))
	for _, r := range records {
		rec, err := r.libdnsRecord()
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := acquireWriteToken(ctx); err != nil {
		return nil, err
	}
	defer releaseWriteToken()

	return p.appendRecords(ctx, zone, records)
}

func (p *Provider) appendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var added []libdns.Record
	for _, rec := range records {
		rr := rec.RR()
		if rr.TTL <= 0 {
			rr.TTL = defaultTTL
		}

		if err := p.addRecord(ctx, zone, rr); err != nil {
			return added, err
		}

		out, err := rr.Parse()
		if err != nil {
			return added, err
		}
		added = append(added, out)
	}
	return added, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := acquireWriteToken(ctx); err != nil {
		return nil, err
	}
	defer releaseWriteToken()

	existing, err := p.getRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	type rrset struct{ name, kind string }
	sets := map[rrset]bool{}
	for _, rec := range records {
		rr := rec.RR()
		sets[rrset{relativeName(rr.Name, zone), rr.Type}] = true
	}

	for _, r := range existing {
		if sets[rrset{r.name, r.kind}] {
			if err := p.deleteRecord(ctx, zone, r); err != nil {
				return nil, err
			}
		}
	}

	return p.appendRecords(ctx, zone, records)
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := acquireWriteToken(ctx); err != nil {
		return nil, err
	}
	defer releaseWriteToken()

	existing, err := p.getRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	var deleted []libdns.Record
	for _, rec := range records {
		rr := rec.RR()
		for _, r := range existing {
			if !r.matches(rr, zone) {
				continue
			}
			if err := p.deleteRecord(ctx, zone, r); err != nil {
				return deleted, err
			}

			out, err := r.libdnsRecord()
			if err != nil {
				return deleted, err
			}
			deleted = append(deleted, out)
		}
	}
	return deleted, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)

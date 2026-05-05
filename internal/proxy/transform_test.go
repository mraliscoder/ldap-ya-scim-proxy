package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestSplitFullName(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantGiven   string
		wantSurname string
	}{
		{"two parts", "Эдуард Ильин", "Эдуард", "Ильин"},
		{"single token", "Иван", "Иван", ""},
		{"surrounding and inner whitespace", "  Анна   Петрова  ", "Анна", "Петрова"},
		{"hyphenated parts", "Анна-Мария Петрова-Водкина", "Анна-Мария", "Петрова-Водкина"},
		{"three tokens keep tail together", "Иван Сергеевич Петров", "Иван", "Сергеевич Петров"},
		{"empty", "", "", ""},
		{"only spaces", "   ", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, s := SplitFullName(tc.in)
			if g != tc.wantGiven || s != tc.wantSurname {
				t.Errorf("SplitFullName(%q) = (%q, %q); want (%q, %q)",
					tc.in, g, s, tc.wantGiven, tc.wantSurname)
			}
		})
	}
}

// silentLog discards log output so tests don't pollute stdout.
func silentLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

func encodeAndReparse(t *testing.T, p *ber.Packet) *ber.Packet {
	t.Helper()
	rebuildPacket(p)
	raw := p.Bytes()
	out, err := ber.ReadPacket(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("re-parse failed: %v", err)
	}
	return out
}

func newSearchResultEntry(messageID int64, dn string, attrs map[string][]string) *ber.Packet {
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))

	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tagSearchResultEntry, nil, "SearchResultEntry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "objectName"))

	attrsSeq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for name, values := range attrs {
		attrsSeq.AppendChild(buildAttribute(name, values))
	}
	op.AppendChild(attrsSeq)
	envelope.AppendChild(op)
	return envelope
}

func entryAttrs(packet *ber.Packet) map[string][]string {
	out := map[string][]string{}
	if len(packet.Children) < 2 || len(packet.Children[1].Children) < 2 {
		return out
	}
	for _, attr := range packet.Children[1].Children[1].Children {
		if len(attr.Children) < 2 {
			continue
		}
		name := readString(attr.Children[0])
		values := []string{}
		for _, v := range attr.Children[1].Children {
			values = append(values, readString(v))
		}
		out[name] = values
	}
	return out
}

func TestTransformSearchResultEntry_UserWithDisplayName(t *testing.T) {
	entry := newSearchResultEntry(1, "uid=eilin,ou=users,dc=example,dc=org", map[string][]string{
		attrObjectClass: {"top", "person", "inetOrgPerson"},
		attrDisplayName: {"Эдуард Ильин"},
		attrCN:          {"Эдуард Ильин"},
		"mail":          {"eilin@example.org"},
	})
	transformSearchResultEntry(entry, nil, silentLog())
	got := entryAttrs(encodeAndReparse(t, entry))

	if v := got[attrGivenName]; len(v) != 1 || v[0] != "Эдуард" {
		t.Errorf("givenName = %v; want [Эдуард]", v)
	}
	if v := got[attrSurname]; len(v) != 1 || v[0] != "Ильин" {
		t.Errorf("sn = %v; want [Ильин]", v)
	}
	if v := got["mail"]; len(v) != 1 || v[0] != "eilin@example.org" {
		t.Errorf("mail unexpectedly altered: %v", v)
	}
	if v := got[attrDisplayName]; len(v) != 1 || v[0] != "Эдуард Ильин" {
		t.Errorf("displayName unexpectedly altered: %v", v)
	}
}

func TestTransformSearchResultEntry_UserFallbackToName(t *testing.T) {
	entry := newSearchResultEntry(2, "uid=u,dc=example,dc=org", map[string][]string{
		attrObjectClass: {"person"},
		attrName:        {"Иван Сергеевич Петров"},
	})
	transformSearchResultEntry(entry, nil, silentLog())
	got := entryAttrs(encodeAndReparse(t, entry))

	if v := got[attrGivenName]; len(v) != 1 || v[0] != "Иван" {
		t.Errorf("givenName = %v; want [Иван]", v)
	}
	if v := got[attrSurname]; len(v) != 1 || v[0] != "Сергеевич Петров" {
		t.Errorf("sn = %v; want [Сергеевич Петров]", v)
	}
}

func TestTransformSearchResultEntry_UserFallbackToCN(t *testing.T) {
	entry := newSearchResultEntry(3, "uid=u,dc=example,dc=org", map[string][]string{
		attrObjectClass: {"organizationalPerson"},
		attrCN:          {"Иван"},
	})
	transformSearchResultEntry(entry, nil, silentLog())
	got := entryAttrs(encodeAndReparse(t, entry))

	if v := got[attrGivenName]; len(v) != 1 || v[0] != "Иван" {
		t.Errorf("givenName = %v; want [Иван]", v)
	}
	if _, present := got[attrSurname]; present {
		t.Errorf("sn must be absent for single-token name; got %v", got[attrSurname])
	}
}

func TestTransformSearchResultEntry_GroupSkipped(t *testing.T) {
	entry := newSearchResultEntry(4, "cn=admins,ou=groups,dc=example,dc=org", map[string][]string{
		attrObjectClass: {"top", "group"},
		attrCN:          {"admins"},
		attrDisplayName: {"Some Display"},
	})
	transformSearchResultEntry(entry, nil, silentLog())
	got := entryAttrs(encodeAndReparse(t, entry))

	if _, ok := got[attrGivenName]; ok {
		t.Errorf("givenName must not appear on group entries")
	}
	if _, ok := got[attrSurname]; ok {
		t.Errorf("sn must not appear on group entries")
	}
}

func TestTransformSearchResultEntry_OverwritesExisting(t *testing.T) {
	entry := newSearchResultEntry(5, "uid=u,dc=example,dc=org", map[string][]string{
		attrObjectClass: {"inetOrgPerson"},
		attrDisplayName: {"Анна Петрова"},
		attrGivenName:   {"OLD"},
		attrSurname:     {"OLDER"},
	})
	transformSearchResultEntry(entry, nil, silentLog())
	got := entryAttrs(encodeAndReparse(t, entry))

	if v := got[attrGivenName]; len(v) != 1 || v[0] != "Анна" {
		t.Errorf("givenName = %v; want [Анна]", v)
	}
	if v := got[attrSurname]; len(v) != 1 || v[0] != "Петрова" {
		t.Errorf("sn = %v; want [Петрова]", v)
	}
}

func TestTransformSearchResultEntry_NoSourcePassthrough(t *testing.T) {
	entry := newSearchResultEntry(6, "uid=u,dc=example,dc=org", map[string][]string{
		attrObjectClass: {"person"},
		"mail":          {"u@example.org"},
	})
	transformSearchResultEntry(entry, nil, silentLog())
	got := entryAttrs(encodeAndReparse(t, entry))

	if _, ok := got[attrGivenName]; ok {
		t.Errorf("givenName must not be added when source is missing")
	}
	if _, ok := got[attrSurname]; ok {
		t.Errorf("sn must not be added when source is missing")
	}
}

func TestTransformSearchResultEntry_StripsInjectedAttrs(t *testing.T) {
	entry := newSearchResultEntry(7, "uid=u,dc=example,dc=org", map[string][]string{
		attrObjectClass: {"person"},
		attrDisplayName: {"Анна Петрова"},
		attrName:        {"name-value"},
		attrCN:          {"cn-value"},
	})
	// Simulate that the proxy injected displayName, name, cn into the request,
	// so it must strip them from the response.
	transformSearchResultEntry(entry, []string{attrDisplayName, attrName, attrCN}, silentLog())
	got := entryAttrs(encodeAndReparse(t, entry))

	for _, a := range []string{attrDisplayName, attrName, attrCN} {
		if _, ok := got[a]; ok {
			t.Errorf("%s should be stripped from response", a)
		}
	}
	if v := got[attrGivenName]; len(v) != 1 || v[0] != "Анна" {
		t.Errorf("givenName = %v; want [Анна]", v)
	}
	if v := got[attrSurname]; len(v) != 1 || v[0] != "Петрова" {
		t.Errorf("sn = %v; want [Петрова]", v)
	}
}

func newSearchRequest(messageID int64, attrs []string) *ber.Packet {
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))

	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tagSearchRequest, nil, "SearchRequest")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dc=example,dc=org", "baseObject"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(2), "scope"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "derefAliases"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "sizeLimit"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "timeLimit"))
	op.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	// Filter: presence (objectClass=*)  =  [APPLICATION 7] OctetString "objectClass"
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "objectClass", "presence filter"))

	attrsList := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, a := range attrs {
		attrsList.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a, "attribute"))
	}
	op.AppendChild(attrsList)
	envelope.AppendChild(op)
	return envelope
}

func searchRequestAttrs(packet *ber.Packet) []string {
	out := []string{}
	if len(packet.Children) < 2 || len(packet.Children[1].Children) < 8 {
		return out
	}
	for _, a := range packet.Children[1].Children[7].Children {
		out = append(out, readString(a))
	}
	return out
}

func TestMaybeRewriteSearchRequest_AddsMissingSources(t *testing.T) {
	req := newSearchRequest(10, []string{"givenName", "sn", "mail"})
	added := maybeRewriteSearchRequest(req)

	wantAdded := map[string]bool{
		"displayName": true, "name": true, "cn": true, "objectClass": true,
	}
	if len(added) != len(wantAdded) {
		t.Fatalf("added = %v; want %d items", added, len(wantAdded))
	}
	for _, a := range added {
		if !wantAdded[a] {
			t.Errorf("unexpected added attribute %q", a)
		}
	}

	got := searchRequestAttrs(encodeAndReparse(t, req))
	gotJoined := strings.Join(got, ",")
	for _, must := range []string{"givenName", "sn", "mail", "displayName", "name", "cn", "objectClass"} {
		if !strings.Contains(gotJoined, must) {
			t.Errorf("attribute list missing %q after rewrite: %v", must, got)
		}
	}
}

func TestMaybeRewriteSearchRequest_AddsObjectClassWhenSourcePresent(t *testing.T) {
	// displayName is already requested but objectClass is not — proxy still
	// needs objectClass to detect user entries, so it must be injected.
	req := newSearchRequest(11, []string{"givenName", "sn", "displayName"})
	added := maybeRewriteSearchRequest(req)
	if len(added) != 1 || strings.ToLower(added[0]) != "objectclass" {
		t.Fatalf("expected objectClass to be added; got %v", added)
	}
	got := searchRequestAttrs(encodeAndReparse(t, req))
	gotJoined := strings.Join(got, ",")
	if !strings.Contains(strings.ToLower(gotJoined), "objectclass") {
		t.Errorf("attribute list missing objectClass after rewrite: %v", got)
	}
}

func TestMaybeRewriteSearchRequest_AddsObjectClassAndSources(t *testing.T) {
	// Neither sources nor objectClass — should add all four.
	req := newSearchRequest(15, []string{"givenName", "sn", "mail"})
	added := maybeRewriteSearchRequest(req)
	wantAdded := map[string]bool{
		"displayName": true, "name": true, "cn": true, "objectClass": true,
	}
	if len(added) != len(wantAdded) {
		t.Fatalf("added = %v; want 4 items", added)
	}
	for _, a := range added {
		if !wantAdded[a] {
			t.Errorf("unexpected added attribute %q", a)
		}
	}
}

func TestMaybeRewriteSearchRequest_PassThroughWhenWildcard(t *testing.T) {
	req := newSearchRequest(12, []string{"*"})
	added := maybeRewriteSearchRequest(req)
	if len(added) != 0 {
		t.Errorf("must not add anything when wildcard is requested; added=%v", added)
	}
	got := searchRequestAttrs(encodeAndReparse(t, req))
	if len(got) != 1 || got[0] != "*" {
		t.Errorf("attribute list unexpectedly altered for wildcard: %v", got)
	}
}

func TestMaybeRewriteSearchRequest_PassThroughWhenEmptyList(t *testing.T) {
	req := newSearchRequest(13, nil)
	added := maybeRewriteSearchRequest(req)
	if len(added) != 0 {
		t.Errorf("must not add anything when attribute list is empty; added=%v", added)
	}
}

func TestMaybeRewriteSearchRequest_PassThroughWhenIrrelevant(t *testing.T) {
	req := newSearchRequest(14, []string{"mail", "uid"})
	added := maybeRewriteSearchRequest(req)
	if len(added) != 0 {
		t.Errorf("must not add anything when neither givenName nor sn is requested; added=%v", added)
	}
}

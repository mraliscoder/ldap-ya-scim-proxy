package proxy

import (
	"log/slog"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const (
	attrGivenName   = "givenName"
	attrSurname     = "sn"
	attrDisplayName = "displayName"
	attrName        = "name"
	attrCN          = "cn"
	attrObjectClass = "objectClass"
)

// userObjectClasses lists objectClass values that mark an entry as a user.
// Compared case-insensitively.
var userObjectClasses = map[string]struct{}{
	"person":               {},
	"inetorgperson":        {},
	"organizationalperson": {},
	"user":                 {},
}

// SplitFullName splits a full name string into givenName and sn following
// the rules from the spec:
//   - trim outer whitespace
//   - split on the first space (strings.SplitN(s, " ", 2))
//   - left part -> givenName, right part -> sn (with surrounding whitespace
//     trimmed so collapsed runs of spaces between parts don't leak through)
//   - empty input -> ("", "")
//   - single token -> (token, "")
func SplitFullName(s string) (given, surname string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	parts := strings.SplitN(s, " ", 2)
	given = parts[0]
	if len(parts) > 1 {
		surname = strings.TrimSpace(parts[1])
	}
	return
}

// transformSearchResultEntry rewrites givenName/sn for user entries derived
// from displayName/name/cn, then strips any source attributes that the proxy
// itself injected into the request (so the client only sees what it asked for).
//
// Mutates packet in place. packet must be a full LDAPMessage whose protocolOp
// is SearchResultEntry ([APPLICATION 4]). Returns true if the packet was
// modified — caller must rebuildPacket(packet) before serializing.
func transformSearchResultEntry(packet *ber.Packet, stripAttrs []string, log *slog.Logger) bool {
	if len(packet.Children) < 2 {
		return false
	}
	protoOp := packet.Children[1]
	if protoOp.ClassType != ber.ClassApplication || protoOp.Tag != tagSearchResultEntry {
		return false
	}
	if len(protoOp.Children) < 2 {
		return false
	}

	dn := readString(protoOp.Children[0])
	attrs := protoOp.Children[1]
	modified := false

	isUser := false
	var displayName, name, cn string

	for _, attr := range attrs.Children {
		if len(attr.Children) < 2 {
			continue
		}
		attrName := strings.ToLower(readString(attr.Children[0]))
		valSet := attr.Children[1]

		switch attrName {
		case "objectclass":
			for _, v := range valSet.Children {
				if _, ok := userObjectClasses[strings.ToLower(readString(v))]; ok {
					isUser = true
				}
			}
		case "displayname":
			if len(valSet.Children) > 0 {
				displayName = readString(valSet.Children[0])
			}
		case "name":
			if len(valSet.Children) > 0 {
				name = readString(valSet.Children[0])
			}
		case "cn":
			if len(valSet.Children) > 0 {
				cn = readString(valSet.Children[0])
			}
		}
	}

	if isUser {
		source := firstNonEmpty(displayName, name, cn)
		if source != "" {
			given, surname := SplitFullName(source)
			rebuildAttrs := make([]*ber.Packet, 0, len(attrs.Children)+2)
			for _, attr := range attrs.Children {
				if len(attr.Children) < 1 {
					rebuildAttrs = append(rebuildAttrs, attr)
					continue
				}
				n := strings.ToLower(readString(attr.Children[0]))
				if n == "givenname" || n == "sn" {
					continue
				}
				rebuildAttrs = append(rebuildAttrs, attr)
			}
			if given != "" {
				rebuildAttrs = append(rebuildAttrs, buildAttribute(attrGivenName, []string{given}))
			}
			if surname != "" {
				rebuildAttrs = append(rebuildAttrs, buildAttribute(attrSurname, []string{surname}))
			}
			attrs.Children = rebuildAttrs
			modified = true
			log.Debug("entry transformed",
				"dn", dn,
				"source_attr", sourceLabel(displayName, name, cn),
				"given_set", given != "",
				"sn_set", surname != "",
			)
		}
	}

	if len(stripAttrs) > 0 {
		stripSet := make(map[string]struct{}, len(stripAttrs))
		for _, a := range stripAttrs {
			stripSet[strings.ToLower(a)] = struct{}{}
		}
		filtered := make([]*ber.Packet, 0, len(attrs.Children))
		stripped := false
		for _, attr := range attrs.Children {
			if len(attr.Children) < 1 {
				filtered = append(filtered, attr)
				continue
			}
			n := strings.ToLower(readString(attr.Children[0]))
			if _, ok := stripSet[n]; ok {
				stripped = true
				continue
			}
			filtered = append(filtered, attr)
		}
		if stripped {
			attrs.Children = filtered
			modified = true
		}
	}
	return modified
}

// maybeRewriteSearchRequest ensures the upstream request carries everything
// the proxy needs to perform the displayName→givenName/sn transformation:
//   - at least one of displayName/name/cn (so we have a source string),
//   - objectClass (so we can detect that the entry is a user).
//
// Returns the list of attribute names the proxy added so the caller can strip
// them from responses to that messageID.
//
// Pass-through cases (returns nil):
//   - empty attribute list (= all user attributes)
//   - "*" present (= all user attributes)
//   - neither givenName nor sn requested
func maybeRewriteSearchRequest(packet *ber.Packet) []string {
	if len(packet.Children) < 2 {
		return nil
	}
	protoOp := packet.Children[1]
	if protoOp.ClassType != ber.ClassApplication || protoOp.Tag != tagSearchRequest {
		return nil
	}
	if len(protoOp.Children) < 8 {
		return nil
	}
	attrsList := protoOp.Children[7]

	if len(attrsList.Children) == 0 {
		return nil
	}

	requested := make(map[string]struct{}, len(attrsList.Children))
	for _, a := range attrsList.Children {
		n := strings.ToLower(strings.TrimSpace(readString(a)))
		if n == "*" {
			return nil
		}
		requested[n] = struct{}{}
	}

	_, wantsGiven := requested["givenname"]
	_, wantsSn := requested["sn"]
	if !wantsGiven && !wantsSn {
		return nil
	}

	added := make([]string, 0, 4)
	appendAttr := func(name string) {
		attrsList.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "Attribute"))
		added = append(added, name)
	}

	_, hasDisplay := requested["displayname"]
	_, hasName := requested["name"]
	_, hasCN := requested["cn"]
	if !hasDisplay && !hasName && !hasCN {
		appendAttr(attrDisplayName)
		appendAttr(attrName)
		appendAttr(attrCN)
	}

	if _, hasObjectClass := requested["objectclass"]; !hasObjectClass {
		appendAttr(attrObjectClass)
	}

	if len(added) == 0 {
		return nil
	}
	return added
}

func buildAttribute(name string, values []string) *ber.Packet {
	attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
	attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "type"))
	valSet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
	for _, v := range values {
		valSet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "value"))
	}
	attr.AppendChild(valSet)
	return attr
}

func readString(p *ber.Packet) string {
	if p == nil {
		return ""
	}
	if s, ok := p.Value.(string); ok {
		return s
	}
	if p.Data != nil {
		return p.Data.String()
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func sourceLabel(displayName, name, cn string) string {
	switch {
	case displayName != "":
		return attrDisplayName
	case name != "":
		return attrName
	case cn != "":
		return attrCN
	default:
		return ""
	}
}

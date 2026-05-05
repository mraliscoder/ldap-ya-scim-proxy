package proxy

import (
	"bytes"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// LDAP protocol op tags (APPLICATION class). See RFC 4511 §4.
const (
	tagBindRequest         ber.Tag = 0
	tagBindResponse        ber.Tag = 1
	tagUnbindRequest       ber.Tag = 2
	tagSearchRequest       ber.Tag = 3
	tagSearchResultEntry   ber.Tag = 4
	tagSearchResultDone    ber.Tag = 5
	tagModifyRequest       ber.Tag = 6
	tagAddRequest          ber.Tag = 8
	tagDelRequest          ber.Tag = 10
	tagModifyDNRequest     ber.Tag = 12
	tagAbandonRequest      ber.Tag = 16
	tagSearchResultRef     ber.Tag = 19
	tagExtendedRequest     ber.Tag = 23
	tagExtendedResponse    ber.Tag = 24
	tagIntermediateResp    ber.Tag = 25
)

// getMessageInfo returns (messageID, protocolOp tag, opClass) for an LDAP
// envelope packet. opClass == ber.ClassApplication for regular ops.
func getMessageInfo(packet *ber.Packet) (messageID int64, opTag ber.Tag, opClass ber.Class) {
	if len(packet.Children) < 2 {
		return 0, 0, 0
	}
	switch v := packet.Children[0].Value.(type) {
	case int64:
		messageID = v
	case uint64:
		messageID = int64(v)
	case int:
		messageID = int64(v)
	}
	op := packet.Children[1]
	return messageID, op.Tag, op.ClassType
}

// searchBaseDN extracts the base DN from a SearchRequest envelope.
func searchBaseDN(packet *ber.Packet) string {
	if len(packet.Children) < 2 || len(packet.Children[1].Children) < 1 {
		return ""
	}
	return readString(packet.Children[1].Children[0])
}

// rebuildPacket walks the packet tree bottom-up and rewrites each constructed
// packet's Data buffer from the current Children slice. asn1-ber's Bytes()
// reads from Data, which becomes stale whenever we mutate Children directly
// (or AppendChild into a descendant after the parent was already serialized).
// Call this on the envelope before serializing any modified packet.
func rebuildPacket(p *ber.Packet) {
	if p == nil {
		return
	}
	for _, c := range p.Children {
		rebuildPacket(c)
	}
	if len(p.Children) > 0 {
		children := p.Children
		p.Children = make([]*ber.Packet, 0, len(children))
		p.Data = new(bytes.Buffer)
		for _, c := range children {
			p.AppendChild(c)
		}
	}
}

// searchScope extracts the scope from a SearchRequest envelope.
func searchScope(packet *ber.Packet) int {
	if len(packet.Children) < 2 || len(packet.Children[1].Children) < 2 {
		return -1
	}
	switch v := packet.Children[1].Children[1].Value.(type) {
	case int64:
		return int(v)
	case uint64:
		return int(v)
	case int:
		return v
	}
	return -1
}

package fwruleprocessor

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
)

// RulesFingerprint returns a digest of every field of every rule, in order. The map entries
// computed from a rule list depend only on that ordered list and on the processor's fixed
// configuration, so a caller that already programmed a map from one list can skip computing
// another with the same fingerprint. Order matters because rules of equal prefix length are
// processed in input order. (The entries are not byte-for-byte reproducible: L4 entries within
// a value come out in map order, which also decides which ports survive the per-CIDR limit.
// Every such output is a valid result for the rules, and a skip keeps whichever one the map
// already holds.)
//
// Each string is length-prefixed and each optional value carries a presence byte, so no two
// different rule lists can serialize to the same bytes. A field added to EbpfFirewallRules or
// v1alpha1.Port must be added here too; TestRulesFingerprint_CoversEveryField fails until it is.
func RulesFingerprint(rules []EbpfFirewallRules) string {
	buf := make([]byte, 0, 64*len(rules)+8)
	buf = appendInt(buf, int64(len(rules)))
	for i := range rules {
		r := &rules[i]
		buf = appendInt(buf, int64(r.Priority))
		buf = appendString(buf, string(r.Action))
		buf = appendString(buf, r.DomainName)
		buf = appendString(buf, string(r.IPCidr))
		buf = appendInt(buf, int64(len(r.Except)))
		for _, except := range r.Except {
			buf = appendString(buf, string(except))
		}
		buf = appendInt(buf, int64(len(r.L4Info)))
		for _, port := range r.L4Info {
			buf = appendPort(buf, port)
		}
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

func appendPort(buf []byte, port v1alpha1.Port) []byte {
	if port.Protocol == nil {
		buf = append(buf, 0)
	} else {
		buf = append(buf, 1)
		buf = appendString(buf, string(*port.Protocol))
	}
	buf = appendOptionalInt32(buf, port.Port)
	return appendOptionalInt32(buf, port.EndPort)
}

func appendOptionalInt32(buf []byte, v *int32) []byte {
	if v == nil {
		return append(buf, 0)
	}
	return appendInt(append(buf, 1), int64(*v))
}

func appendString(buf []byte, s string) []byte {
	return append(appendInt(buf, int64(len(s))), s...)
}

func appendInt(buf []byte, v int64) []byte {
	return binary.LittleEndian.AppendUint64(buf, uint64(v))
}

// mayhem/kat/main.go — dynamically-linked known-answer probe for openyurt's
// iptables-save dump / rule parser. `import "C"` (cgo) forces a DYNAMICALLY
// LINKED binary so the gate's LD_PRELOAD sabotage shim can neuter it (a
// statically-linked Go binary would be immune, giving a false-green oracle — the
// trap netnew §4 warns about with `go test` alone).
//
// It imports the build-time-staged iptables mini-module (created by
// mayhem/build.sh at _mayhem_harness/iptables) and runs KATRun(), which drives
// fixed dumps/rules through the REAL ParseIPTablesDump / ParseRule code, then
// prints each result in a fixed, greppable format for mayhem/test.sh to assert.
package main

// #include <stdint.h>
import "C"

import (
	"fmt"

	ipt "openyurt.local/mayhemiptables"
)

func main() {
	r := ipt.KATRun()
	fmt.Printf("KAT_TABLE_COUNT=%d\n", r.TableCount)
	fmt.Printf("KAT_TABLE_NAME=%s\n", r.TableName)
	fmt.Printf("KAT_CHAIN_COUNT=%d\n", r.ChainCount)
	fmt.Printf("KAT_CHAIN_NAME=%s\n", r.ChainName)
	fmt.Printf("KAT_PACKETS=%d\n", r.Packets)
	fmt.Printf("KAT_BYTES=%d\n", r.Bytes)
	fmt.Printf("KAT_RULE_COUNT=%d\n", r.RuleCount)
	fmt.Printf("KAT_RULE_CHAIN=%s\n", r.RuleChain)
	fmt.Printf("KAT_RULE_SOURCE=%s\n", r.RuleSource)
	fmt.Printf("KAT_RULE_PROTO=%s\n", r.RuleProto)
	fmt.Printf("KAT_RULE_DPORT=%s\n", r.RuleDport)
	fmt.Printf("KAT_RULE_JUMP=%s\n", r.RuleJump)
	fmt.Printf("KAT_NEG_DEST=%s\n", r.NegDest)
	fmt.Printf("KAT_NEG_NEGATED=%v\n", r.NegNegated)
	fmt.Printf("KAT_NEG_JUMP=%s\n", r.NegJump)
}

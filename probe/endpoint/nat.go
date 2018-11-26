// +build linux

package endpoint

import (
	"fmt"
	"net"
	"strconv"

	"github.com/typetypetype/conntrack"

	"github.com/weaveworks/scope/report"
)

// This is our 'abstraction' of the endpoint that have been rewritten by NAT.
// Original is the private IP that has been rewritten.
type endpointMapping struct {
	originalIP   net.IP
	originalPort uint16

	rewrittenIP   net.IP
	rewrittenPort uint16
}

// natMapper rewrites a report to deal with NAT'd connections.
type natMapper struct {
	flowWalker
}

func makeNATMapper(fw flowWalker) natMapper {
	return natMapper{fw}
}

func toMapping(f conntrack.Conn) *endpointMapping {
	var mapping endpointMapping
	if f.Orig.Src.Equal(f.Reply.Dst) {
		mapping = endpointMapping{
			originalIP:    f.Reply.Src,
			originalPort:  f.Reply.SrcPort,
			rewrittenIP:   f.Orig.Dst,
			rewrittenPort: f.Orig.DstPort,
		}
	} else {
		mapping = endpointMapping{
			originalIP:    f.Orig.Src,
			originalPort:  f.Orig.SrcPort,
			rewrittenIP:   f.Reply.Dst,
			rewrittenPort: f.Reply.DstPort,
		}
	}

	return &mapping
}

func endpointNodeID(scope string, ip net.IP, port uint16) string {
	return report.MakeEndpointNodeID(scope, "", ip.String(), strconv.Itoa(int(port)))
}

var count int

// applyNAT duplicates Nodes in the endpoint topology of a report, based on
// the NAT table.
func (n natMapper) applyNAT(rpt report.Report, scope string) {
	n.flowWalker.walkFlows(func(f conntrack.Conn, _ bool) {
		if (f.Status & conntrack.IPS_DST_NAT) != 0 {
			fromID := endpointNodeID(scope, f.Reply.Dst, f.Reply.DstPort)
			fromNode, ok := rpt.Endpoint.Nodes[fromID]
			if !ok {
				if count < 5 {
					fmt.Printf("Not found %s\n", fromID)
				}
				return
			}

			toID := endpointNodeID(scope, f.Orig.Dst, f.Orig.DstPort)

			// replace destination with reply source
			replySrcID := endpointNodeID(scope, f.Reply.Src, f.Reply.SrcPort)
			if replySrcID != toID {
				if count < 5 {
					fmt.Printf("replace destination %s with reply source: %s\n", toID, replySrcID)
				}
				fromNode.Adjacency = fromNode.Adjacency.Minus(toID)
				fromNode = fromNode.WithAdjacent(replySrcID)
			}

			// we can't simply replace the source - it may have adjacencies to other things (?)
			origSrcID := endpointNodeID(scope, f.Orig.Src, f.Orig.SrcPort)
			if origSrcID != fromID {
				if count < 5 {
					fmt.Printf("add copy of source %s with original source: %s\n", fromID, origSrcID)
				}
				//delete(rpt.Endpoint.Nodes, fromID)
			}
			rpt.Endpoint.AddNode(fromNode.WithID(origSrcID).WithLatests(map[string]string{
				CopyOf: fromID,
			}))
		}
	})
}

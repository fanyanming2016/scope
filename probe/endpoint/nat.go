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

/*

Some examples of connections with NAT:

Pod to pod via Kubernetes service
  picked up by ebpf as 10.32.0.16:47600->10.105.173.176:5432 and 10.32.0.6:5432 (??)
  NAT IPS_DST_NAT orig: 10.32.0.16:47600->10.105.173.176:5432, reply: 10.32.0.6:5432->10.32.0.16:47600
  We want: 10.32.0.16:47600->10.32.0.6:5432
   - replace the destination with the NAT reply source

Incoming from outside the cluster to a NodePort:
  picked up by ebpf as 10.32.0.1:13488->10.32.0.7:80
  NAT: IPS_SRC_NAT IPS_DST_NAT orig: 37.157.33.76:13488->172.31.2.17:30081, reply: 10.32.0.7:80->10.32.0.1:13488
  We want: 37.157.33.76:13488->10.32.0.7:80
   - replace the source with the NAT original source

Outgoing from a pod:
  picked up by ebpf as 10.32.0.7:36078->18.221.99.178:443
  NAT:  IPS_SRC_NAT orig: 10.32.0.7:36078->18.221.99.178:443, reply: 18.221.99.178:443->172.31.2.17:36078
  We want: 10.32.0.7:36078->18.221.99.178:443
   - leave it alone.

All of the above can be satisfied by these rules:
  For SRC_NAT replace the source with the NAT original source
  For DST_NAT replace the destination with the NAT reply source
*/

var count int

// applyNAT modifies Nodes in the endpoint topology of a report, based on
// the NAT table.
func (n natMapper) applyNAT(rpt report.Report, scope string) {
	if count < 5 {
		for id, node := range rpt.Endpoint.Nodes {
			fmt.Printf("Endpoint %s: %v\n", id, node)
		}
	}
	n.flowWalker.walkFlows(func(f conntrack.Conn, _ bool) {
		if count < 5 {
			fmt.Printf("NAT: %x, type: %d, state: %s, status: %s, orig: %v, reply: %v\n", f.CtId, f.MsgType, f.TCPState, f.Status.String(), f.Orig, f.Reply)
		}

		fromID := endpointNodeID(scope, f.Reply.Dst, f.Reply.DstPort)
		fromNode, ok := rpt.Endpoint.Nodes[fromID]
		if !ok {
			if count < 5 {
				fmt.Printf("Not found %s\n", fromID)
			}
			return
		}

		if (f.Status & conntrack.IPS_SRC_NAT) != 0 {
			// add a copy of the from node with a new ID
			origSrcID := endpointNodeID(scope, f.Orig.Src, f.Orig.SrcPort)
			if origSrcID != fromID {
				if count < 5 {
					fmt.Printf("add copy of source %s with original source: %s\n", fromID, origSrcID)
				}
				newNode := fromNode.WithID(origSrcID).WithLatests(map[string]string{
					CopyOf: fromID,
				})
				rpt.Endpoint.AddNode(newNode)

				// remove the natted connection from the original node, and remove the node if none left
				toID := endpointNodeID(scope, f.Reply.Src, f.Reply.SrcPort)
				fromNode.Adjacency = fromNode.Adjacency.Minus(toID)
				if len(fromNode.Adjacency) == 0 {
					delete(rpt.Endpoint.Nodes, fromID)
				} else {
					rpt.Endpoint.Nodes[fromID] = fromNode
				}

				fromNode = newNode
			}
		}

		if (f.Status & conntrack.IPS_DST_NAT) != 0 {
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
		}
	})
	count++
}

package witness

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// Two things collide on a port only when they collide on the whole *binding*:
// the protocol, the host address and the port number. `53/tcp` and `53/udp` are
// two different sockets on one number, and so are `127.0.0.1:8080` and
// `192.168.1.10:8080`. Comparing the number alone — which is what this rule used
// to do — turns both of those into a blocker that stops a deployment which would
// have worked.
//
// Some pairs cannot be decided from what the tool reads offline: an IPv6 wildcard
// also answers IPv4 unless `net.ipv6.bindv6only` is set, a publish with no
// host_ip gets an IPv6 binding only when the daemon has IPv6 enabled, and a
// `host_ip` left as an unresolved `${VARIABLE}` is not an address at all. Those
// answer overlapUnknown, which the rule reports as a warning naming the command
// that settles it. Calling them "no conflict" would be the dishonest half of the
// second promise; calling them a blocker is the false blocker this rule is being
// fixed to stop producing.

type overlap int

const (
	overlapNone overlap = iota
	overlapUnknown
	overlapYes
)

// portClaim is one side of the comparison: a protocol, an address and a port,
// reduced from either a manifest publish or a listening socket.
type portClaim struct {
	protocol string // base protocol, lower case: "tcp", "udp", "sctp", …
	port     int
	address  string // as recorded, brackets stripped; "" when none was named
	ip       net.IP // the parsed address; nil when none was named or it is unreadable
	anyAddr  bool   // the literal "*" that `ss` prints: every interface, both families
	readable bool   // the recorded address could be understood as an address
}

// claimFromMapping reduces one published host port of a manifest service — or of
// an existing container, which Docker reports in the same shape.
func claimFromMapping(mapping model.PortMapping, port int) portClaim {
	claim := portClaim{
		protocol: baseProtocol(mapping.Protocol),
		port:     port,
		address:  strings.Trim(strings.TrimSpace(mapping.HostIP), "[]"),
		readable: true,
	}
	if claim.address == "" {
		return claim
	}
	claim.ip = net.ParseIP(claim.address)
	if claim.ip == nil {
		// `host_ip: ${HOST_IP}` that no .env resolved is left as a literal by the
		// interpolator. It is not an address, and guessing which one it would have
		// become is worse than saying so.
		claim.readable = false
	}
	return claim
}

// claimFromSocket reduces one listening socket read from /proc/net (or from `ss`,
// on a host where /proc/net was hidden).
func claimFromSocket(socket model.Port) portClaim {
	claim := portClaim{
		protocol: baseProtocol(socket.Protocol),
		port:     socket.Port,
		address:  strings.Trim(strings.TrimSpace(socket.Address), "[]"),
		readable: true,
	}
	if claim.address == "" || claim.address == "*" {
		// `ss` prints "*" for a socket bound to every interface, and the collector
		// already classifies it as all-interfaces exposure. It is a wildcard, not
		// an address the tool failed to read.
		claim.anyAddr = true
		claim.address = "*"
		return claim
	}
	claim.ip = net.ParseIP(claim.address)
	if claim.ip == nil {
		claim.readable = false
	}
	return claim
}

// baseProtocol strips the address-family suffix. "tcp6" is the name of the table
// the socket was read from, not a protocol that cannot collide with "tcp" — the
// family question is settled by the address, because the collector normalises an
// IPv4-mapped address out of /proc/net/tcp6 into dotted form.
func baseProtocol(protocol string) string {
	p := strings.ToLower(strings.TrimSpace(protocol))
	if p == "" {
		return "tcp" // Compose's default when the publish names no protocol
	}
	return strings.TrimSuffix(p, "6")
}

// observableProtocol reports whether a listener of that protocol is something
// this tool can see at all: the collector reads /proc/net/{tcp,tcp6,udp,udp6} and
// there is no table for anything else.
func observableProtocol(protocol string) bool {
	return protocol == "tcp" || protocol == "udp"
}

// subject renders the binding for Finding.Subject. A publish that names no
// address keeps the old `port/protocol` form, which is both what the reader is
// used to and all there is to say about it.
func (c portClaim) subject() string {
	if c.address == "" {
		return fmt.Sprintf("%d/%s", c.port, c.protocol)
	}
	return net.JoinHostPort(c.address, strconv.Itoa(c.port)) + "/" + c.protocol
}

// describe is the same binding in prose.
func (c portClaim) describe() string {
	if c.address == "" {
		return fmt.Sprintf("port %d/%s on every host address", c.port, c.protocol)
	}
	if c.anyAddr {
		return fmt.Sprintf("port %d/%s on every host address", c.port, c.protocol)
	}
	return fmt.Sprintf("port %d/%s on %s", c.port, c.protocol, c.address)
}

// coverage is what one claim holds inside one address family.
type coverage int

const (
	covNone     coverage = iota // nothing in this family
	covMaybeAll                 // everything in this family, if the host is configured that way
	covAll                      // everything in this family
	covSpecific                 // exactly one address, returned alongside
)

func (c portClaim) coverage(v4 bool) (coverage, net.IP) {
	switch {
	case c.anyAddr:
		return covAll, nil
	case c.address == "":
		// Compose's default. The engine binds every IPv4 address, and adds the IPv6
		// wildcard only when the daemon has IPv6 turned on — which this tool does
		// not read.
		if v4 {
			return covAll, nil
		}
		return covMaybeAll, nil
	case c.ip == nil:
		return covNone, nil // unreadable, and settled before coverage is consulted
	case c.ip.IsUnspecified():
		if isIPv4(c.ip) { // 0.0.0.0
			if v4 {
				return covAll, nil
			}
			return covNone, nil
		}
		// "::" — every IPv6 address, and every IPv4 one too unless
		// net.ipv6.bindv6only is set, which this tool does not read.
		if v4 {
			return covMaybeAll, nil
		}
		return covAll, nil
	case isIPv4(c.ip) == v4:
		return covSpecific, c.ip
	default:
		return covNone, nil
	}
}

// isIPv4 asks the address, not the protocol string: a socket from /proc/net/tcp6
// bound to ::ffff:127.0.0.1 reaches the rule as Address "127.0.0.1", and it does
// collide with an IPv4 publish.
func isIPv4(ip net.IP) bool { return ip.To4() != nil }

// collides answers whether the manifest's binding (want) is held by another one
// (held), and when the answer is "unknown", why.
func collides(want, held portClaim) (overlap, string) {
	if want.port != held.port || want.protocol != held.protocol {
		return overlapNone, ""
	}
	if !want.readable {
		return overlapUnknown, fmt.Sprintf(
			"the manifest binds host address %q, which is not an address — an unresolved variable, most likely — "+
				"so which interface the publish lands on cannot be established from the compose file alone.",
			want.address)
	}
	if !held.readable {
		return overlapUnknown, fmt.Sprintf(
			"the address %q of the socket already on that port could not be read as an IP address.", held.address)
	}

	best, why := overlapNone, ""
	for _, v4 := range []bool{true, false} {
		result, reason := familyOverlap(want, held, v4)
		if result > best {
			best, why = result, reason
		}
	}
	return best, why
}

func familyOverlap(want, held portClaim, v4 bool) (overlap, string) {
	wantCov, wantIP := want.coverage(v4)
	heldCov, heldIP := held.coverage(v4)

	switch {
	case wantCov == covNone || heldCov == covNone:
		return overlapNone, ""
	case wantCov == covMaybeAll || heldCov == covMaybeAll:
		return overlapUnknown, maybeReason(want, held, wantCov, heldCov)
	case wantCov == covSpecific && heldCov == covSpecific && !wantIP.Equal(heldIP):
		return overlapNone, ""
	default:
		return overlapYes, ""
	}
}

func maybeReason(want, held portClaim, wantCov, heldCov coverage) string {
	var parts []string
	if wantCov == covMaybeAll {
		parts = append(parts, sideReason("The manifest", want))
	}
	if heldCov == covMaybeAll {
		parts = append(parts, sideReason("The binding already on that port", held))
	}
	return strings.Join(parts, " ")
}

func sideReason(who string, c portClaim) string {
	if c.address == "" {
		return who + " names no host address, so the engine binds every IPv4 address and adds IPv6 only when the " +
			"daemon has IPv6 enabled — this tool does not read the daemon's configuration."
	}
	return who + " is the IPv6 wildcard [::], which also answers IPv4 connections unless net.ipv6.bindv6only is " +
		"set — this tool does not read that sysctl."
}

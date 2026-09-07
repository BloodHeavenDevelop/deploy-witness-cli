package ports

import "testing"

func TestParseEndpoint(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port int
	}{
		// IPv4 addresses are little-endian words; the port is big-endian.
		{"0100007F:0035", "127.0.0.1", 53},
		{"00000000:0016", "0.0.0.0", 22},
		{"0101A8C0:1F90", "192.168.1.1", 8080},
		// IPv6: four little-endian 32-bit words.
		{"00000000000000000000000000000000:0016", "::", 22},
		{"00000000000000000000000001000000:0277", "::1", 631},
	}

	for _, c := range cases {
		ip, port, err := parseEndpoint(c.in)
		if err != nil {
			t.Errorf("parseEndpoint(%q) failed: %v", c.in, err)
			continue
		}
		if ip.String() != c.ip || port != c.port {
			t.Errorf("parseEndpoint(%q) = %s:%d, want %s:%d", c.in, ip, port, c.ip, c.port)
		}
	}
}

func TestParseEndpointRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "nocolon", "ZZ:0016", "0100007F:ZZZZ", "010000:0016"} {
		if _, _, err := parseEndpoint(in); err == nil {
			t.Errorf("parseEndpoint(%q) should have failed", in)
		}
	}
}

const tcpTable = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 22983 1 0000 100 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 19122 1 0000 100 0
   2: 0100007F:8B1A 0100007F:E0C6 01 00000000:00000000 00:00000000 00000000  1000        0 55501 1 0000 20 0
`

func TestParseTableKeepsOnlyListeners(t *testing.T) {
	got := parseTable(tcpTable, "tcp", nil, nil)
	if len(got) != 2 {
		t.Fatalf("expected 2 listening sockets, got %d: %+v", len(got), got)
	}

	if got[0].Port != 53 || got[0].Exposure != "loopback" {
		t.Errorf("row 0 = %+v, want port 53 on loopback", got[0])
	}
	// A socket on 0.0.0.0 reaches every interface; that distinction is the whole
	// point of the exposure column.
	if got[1].Port != 22 || got[1].Exposure != "all-interfaces" {
		t.Errorf("row 1 = %+v, want port 22 on all interfaces", got[1])
	}
	for _, row := range got {
		if row.State != "LISTEN" {
			t.Errorf("row %+v should be LISTEN", row)
		}
	}
}

const udpTable = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 22990 2 0000 0
   1: 0101A8C0:BB8C 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 60112 2 0000 0
`

func TestParseTableDropsConnectedUDP(t *testing.T) {
	got := parseTable(udpTable, "udp", nil, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 unconnected UDP socket, got %d: %+v", len(got), got)
	}
	if got[0].Port != 53 {
		t.Errorf("kept the wrong socket: %+v", got[0])
	}
}

func TestSocketInode(t *testing.T) {
	if inode, ok := socketInode("socket:[12345]"); !ok || inode != "12345" {
		t.Errorf("socketInode = (%q, %v), want (\"12345\", true)", inode, ok)
	}
	for _, link := range []string{"/dev/null", "pipe:[123]", "socket:123"} {
		if _, ok := socketInode(link); ok {
			t.Errorf("socketInode(%q) should not match", link)
		}
	}
}

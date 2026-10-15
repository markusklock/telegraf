package cisco_urwb

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/plugins/parsers/influx"
	"github.com/influxdata/telegraf/testutil"
)

func TestInit(t *testing.T) {
	tests := []struct {
		name    string
		address string
		allowed []string
		errmsg  string
	}{
		{
			name:    "udp",
			address: "udp://:30000",
		},
		{
			name:    "udp4",
			address: "udp4://127.0.0.1:30000",
		},
		{
			name:    "udp6",
			address: "udp6://[::1]:30000",
		},
		{
			name:    "allowed sources",
			address: "udp://:30000",
			allowed: []string{"10.0.0.0/8", "192.168.1.10", "2001:db8::/32", "::1"},
		},
		{
			name:   "empty service address",
			errmsg: "service_address required",
		},
		{
			name:    "invalid service address",
			address: "udp://[::1",
			errmsg:  "invalid service address",
		},
		{
			name:    "invalid scheme",
			address: "tcp://:30000",
			errmsg:  "invalid scheme",
		},
		{
			name:    "invalid allowed source address",
			address: "udp://:30000",
			allowed: []string{"10.0.0.256"},
			errmsg:  `invalid allowed source "10.0.0.256"`,
		},
		{
			name:    "invalid allowed source network",
			address: "udp://:30000",
			allowed: []string{"10.0.0.0/33"},
			errmsg:  `invalid allowed source "10.0.0.0/33"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &CiscoURWB{
				ServiceAddress: tt.address,
				AllowedSources: tt.allowed,
				Log:            testutil.Logger{},
			}
			err := plugin.Init()
			if tt.errmsg != "" {
				require.ErrorContains(t, err, tt.errmsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAllowedSources(t *testing.T) {
	plugin := &CiscoURWB{
		ServiceAddress: "udp://:30000",
		AllowedSources: []string{"10.1.0.0/16", "192.168.1.10", "2001:db8::/32"},
		Log:            testutil.Logger{},
	}
	require.NoError(t, plugin.Init())

	tests := []struct {
		addr     string
		expected bool
	}{
		{addr: "10.1.2.3", expected: true},
		{addr: "10.2.0.1", expected: false},
		{addr: "192.168.1.10", expected: true},
		{addr: "192.168.1.11", expected: false},
		{addr: "2001:db8::1", expected: true},
		{addr: "2001:db9::1", expected: false},
		{addr: "fe80::1%eth0", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			require.Equal(t, tt.expected, plugin.isAllowed(netip.MustParseAddr(tt.addr)))
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		name   string
		typ    uint16
		data   string
		errmsg string
	}{
		{
			name:   "fhctrl state too short",
			typ:    tlvFHCtrlVehicle,
			data:   "0000",
			errmsg: "state too short: 2 bytes",
		},
		{
			name:   "fhctrl entries misaligned",
			typ:    tlvFHCtrlVehicleMultiRadio,
			data:   strings.Repeat("00", fhctrlStateLen+fhctrlEntryLen-1),
			errmsg: "neighbor entries: length 17 is not a multiple of the entry size 18",
		},
		{
			name:   "titan too short",
			typ:    tlvTitan,
			data:   "0000",
			errmsg: "too short: 2 bytes",
		},
		{
			name:   "eth throughput too short",
			typ:    tlvEthThroughput,
			data:   "00",
			errmsg: "too short: 1 bytes",
		},
		{
			name:   "eth throughput too many TX entries",
			typ:    tlvEthThroughput,
			data:   "0002" + strings.Repeat("00", ethEntryLen),
			errmsg: "number of TX entries 2 exceeds total number of entries 1",
		},
		{
			name:   "multipath truncated route",
			typ:    tlvMultipath,
			data:   "0002",
			errmsg: "truncated route: 2 bytes",
		},
		{
			name:   "multipath without peers",
			typ:    tlvMultipath,
			data:   "00000000",
			errmsg: "route without peers",
		},
		{
			name:   "multipath truncated peers",
			typ:    tlvMultipath,
			data:   "00020000" + "00000001",
			errmsg: "route with 2 peers truncated: 4 bytes",
		},
		{
			name:   "tx stats misaligned",
			typ:    tlvTxStatsMultiRadio,
			data:   strings.Repeat("00", txStatsLen+1),
			errmsg: "length 29 is not a multiple of the entry size 28",
		},
		{
			name:   "rx stats misaligned",
			typ:    tlvRxStatsMultiRadio,
			data:   strings.Repeat("00", rxStatsLen-1),
			errmsg: "length 21 is not a multiple of the entry size 22",
		},
		{
			name:   "handoff truncated entry",
			typ:    tlvHandoffMultiRadio,
			data:   strings.Repeat("00", handoffLen-1),
			errmsg: "truncated entry: 25 bytes",
		},
		{
			name:   "handoff truncated units",
			typ:    tlvHandoffMultiRadioMPO,
			data:   strings.Repeat("00", handoffLen-1) + "02" + "00000001",
			errmsg: "entry with 2 units truncated: 4 bytes",
		},
		{
			name:   "aggregated traffic too short",
			typ:    tlvAggrTrafficMultiRadio,
			data:   "00000000",
			errmsg: "too short: 4 bytes",
		},
		{
			name:   "aggregated traffic wireless entries misaligned",
			typ:    tlvAggrTrafficMultiRadio,
			data:   strings.Repeat("00", aggrEthTrafficLen+1),
			errmsg: "wireless entries: length 1 is not a multiple of the entry size 12",
		},
		{
			name:   "radio config misaligned",
			typ:    tlvRadioConfigMultiRadio,
			data:   strings.Repeat("00", radioConfigLen+2),
			errmsg: "length 22 is not a multiple of the entry size 20",
		},
		{
			name:   "MPO extension misaligned",
			typ:    tlvMPOExt,
			data:   strings.Repeat("00", mpoExtLen-2),
			errmsg: "length 36 is not a multiple of the entry size 38",
		},
		{
			name:   "blocklist misaligned",
			typ:    tlvBlocklistMultiRadio,
			data:   strings.Repeat("00", blocklistLen+3),
			errmsg: "length 15 is not a multiple of the entry size 12",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := hex.DecodeString(tt.data)
			require.NoError(t, err)

			plugin := &CiscoURWB{ServiceAddress: "udp://:30000", Log: testutil.Logger{}}
			require.NoError(t, plugin.Init())

			// Failing TLVs must not produce metrics, only the packet metric is expected
			metrics, err := plugin.decode("127.0.0.1", buildPacket(tt.typ, data), time.Now())
			require.ErrorContains(t, err, tt.errmsg)
			require.Len(t, metrics, 1)
			require.Equal(t, "urwb_packet", metrics[0].Name())
		})
	}
}

func TestCases(t *testing.T) {
	folders, err := os.ReadDir("testcases")
	require.NoError(t, err)

	// Prepare the influx parser for expectations
	parser := &influx.Parser{}
	require.NoError(t, parser.Init())

	for _, f := range folders {
		if !f.IsDir() {
			continue
		}
		testcasePath := filepath.Join("testcases", f.Name())
		configFilename := filepath.Join(testcasePath, "telegraf.conf")
		expectedFilename := filepath.Join(testcasePath, "expected.out")
		expectedErrorFilename := filepath.Join(testcasePath, "expected.err")

		t.Run(f.Name(), func(t *testing.T) {
			// Read the input packets, sorted by filename
			packets, err := readPackets(testcasePath)
			require.NoError(t, err)
			require.NotEmpty(t, packets)

			// Read the expected output if any
			var expected []telegraf.Metric
			if _, err := os.Stat(expectedFilename); err == nil {
				expected, err = testutil.ParseMetricsFromFile(expectedFilename, parser)
				require.NoError(t, err)
			}

			// Read the expected errors if any
			var expectedErrors []string
			if _, err := os.Stat(expectedErrorFilename); err == nil {
				expectedErrors, err = testutil.ParseLinesFromFile(expectedErrorFilename)
				require.NoError(t, err)
				require.NotEmpty(t, expectedErrors)
			}

			// Configure, setup and start the plugin
			cfg := config.NewConfig()
			require.NoError(t, cfg.LoadConfig(configFilename))
			require.Len(t, cfg.Inputs, 1)
			plugin := cfg.Inputs[0].Input.(*CiscoURWB)
			plugin.Log = testutil.Logger{}
			require.NoError(t, plugin.Init())

			var acc testutil.Accumulator
			require.NoError(t, plugin.Start(&acc))
			defer plugin.Stop()

			// Send the packets
			client, err := net.Dial("udp", plugin.conn.LocalAddr().String())
			require.NoError(t, err)
			defer client.Close()
			for _, pkt := range packets {
				_, err := client.Write(pkt)
				require.NoError(t, err)
			}

			// Wait for the expected metrics and errors
			require.Eventuallyf(t, func() bool {
				acc.Lock()
				defer acc.Unlock()
				if acc.NMetrics() < uint64(len(expected)) {
					return false
				}
				msgs := make([]string, 0, len(acc.Errors))
				for _, err := range acc.Errors {
					msgs = append(msgs, err.Error())
				}
				joined := strings.Join(msgs, "\n")
				for _, e := range expectedErrors {
					if !strings.Contains(joined, e) {
						return false
					}
				}
				return true
			}, 3*time.Second, 50*time.Millisecond, "did not receive all metrics (%d/%d) or errors %v", acc.NMetrics(), len(expected), acc.Errors)

			if len(expectedErrors) == 0 {
				require.Empty(t, acc.Errors)
			}
			testutil.RequireMetricsEqual(t, expected, acc.GetTelegrafMetrics(), testutil.IgnoreTime(), testutil.SortMetrics())
		})
	}
}

func FuzzDecode(f *testing.F) {
	// Use the packets of all test-cases as seed corpus
	folders, err := os.ReadDir("testcases")
	require.NoError(f, err)
	for _, folder := range folders {
		if !folder.IsDir() {
			continue
		}
		packets, err := readPackets(filepath.Join("testcases", folder.Name()))
		require.NoError(f, err)
		for _, pkt := range packets {
			f.Add(pkt)
		}
	}

	plugin := &CiscoURWB{ServiceAddress: "udp://:30000", Log: testutil.Logger{Quiet: true}}
	require.NoError(f, plugin.Init())

	f.Fuzz(func(_ *testing.T, data []byte) {
		//nolint:errcheck // Only check for panics on malformed input
		plugin.decode("127.0.0.1", data, time.Now())
	})
}

// readPackets reads the raw packets from the '*.bin' files and the hex encoded
// packets from the '*.hex' files of the given directory. Hex files can contain
// whitespace and comments starting with '#'.
func readPackets(dir string) ([][]byte, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.*"))
	if err != nil {
		return nil, err
	}

	packets := make([][]byte, 0, len(matches))
	for _, fn := range matches {
		var pkt []byte
		switch filepath.Ext(fn) {
		case ".bin":
			if pkt, err = os.ReadFile(fn); err != nil {
				return nil, err
			}
		case ".hex":
			buf, err := os.ReadFile(fn)
			if err != nil {
				return nil, err
			}
			var encoded strings.Builder
			for line := range strings.Lines(string(buf)) {
				line, _, _ = strings.Cut(line, "#")
				encoded.WriteString(strings.Join(strings.Fields(line), ""))
			}
			if pkt, err = hex.DecodeString(encoded.String()); err != nil {
				return nil, err
			}
		default:
			continue
		}
		packets = append(packets, pkt)
	}
	return packets, nil
}

// buildPacket creates a packet with a valid header containing a single TLV
func buildPacket(typ uint16, data []byte) []byte {
	pkt := make([]byte, headerLen+tlvHeaderLen, headerLen+tlvHeaderLen+len(data))
	binary.BigEndian.PutUint32(pkt[0:4], headerMagic)
	binary.BigEndian.PutUint16(pkt[headerLen:headerLen+2], typ)
	binary.BigEndian.PutUint16(pkt[headerLen+2:headerLen+4], uint16(len(data)))
	return append(pkt, data...)
}

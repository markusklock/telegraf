//go:generate ../../../tools/readme_config_includer/generator
package cisco_urwb

import (
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/metric"
	"github.com/influxdata/telegraf/plugins/inputs"
)

//go:embed sample.conf
var sampleConfig string

const (
	headerMagic  = 0xF1CA0005
	headerLen    = 32
	tlvHeaderLen = 4
)

type CiscoURWB struct {
	ServiceAddress string          `toml:"service_address"`
	ReadBufferSize config.Size     `toml:"read_buffer_size"`
	AllowedSources []string        `toml:"allowed_sources"`
	Log            telegraf.Logger `toml:"-"`

	allowed     []netip.Prefix
	unsupported map[uint16]bool
	conn        *net.UDPConn
	wg          sync.WaitGroup
}

type tlv struct {
	typ  uint16
	data []byte
}

// packet holds the information of the packet header shared by all metrics
// decoded from the packet's TLVs.
type packet struct {
	tags      map[string]string
	meshID    uint32
	timestamp time.Time
}

func (*CiscoURWB) SampleConfig() string {
	return sampleConfig
}

func (c *CiscoURWB) Init() error {
	if c.ServiceAddress == "" {
		return errors.New("service_address required")
	}
	u, err := url.Parse(c.ServiceAddress)
	if err != nil {
		return fmt.Errorf("invalid service address %q: %w", c.ServiceAddress, err)
	}
	switch u.Scheme {
	case "udp", "udp4", "udp6":
	default:
		return fmt.Errorf("invalid scheme %q, should be 'udp', 'udp4' or 'udp6'", u.Scheme)
	}

	c.allowed = make([]netip.Prefix, 0, len(c.AllowedSources))
	for _, source := range c.AllowedSources {
		prefix, err := parsePrefix(source)
		if err != nil {
			return fmt.Errorf("invalid allowed source %q: %w", source, err)
		}
		c.allowed = append(c.allowed, prefix)
	}

	c.unsupported = make(map[uint16]bool)

	return nil
}

func (c *CiscoURWB) Start(acc telegraf.Accumulator) error {
	u, err := url.Parse(c.ServiceAddress)
	if err != nil {
		return err
	}
	addr, err := net.ResolveUDPAddr(u.Scheme, u.Host)
	if err != nil {
		return fmt.Errorf("resolving address %q failed: %w", u.Host, err)
	}
	conn, err := net.ListenUDP(u.Scheme, addr)
	if err != nil {
		return fmt.Errorf("listening on %q failed: %w", c.ServiceAddress, err)
	}
	if c.ReadBufferSize > 0 {
		if err := conn.SetReadBuffer(int(c.ReadBufferSize)); err != nil {
			_ = conn.Close()
			return fmt.Errorf("setting read buffer size failed: %w", err)
		}
	}
	c.conn = conn
	c.Log.Infof("Listening on %s://%s", u.Scheme, conn.LocalAddr())

	c.wg.Go(func() {
		c.listen(acc)
	})

	return nil
}

func (*CiscoURWB) Gather(telegraf.Accumulator) error {
	return nil
}

func (c *CiscoURWB) Stop() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.wg.Wait()
}

func (c *CiscoURWB) listen(acc telegraf.Accumulator) {
	// Use the maximum UDP payload size to never truncate packets
	buf := make([]byte, 64*1024)
	for {
		n, src, err := c.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				acc.AddError(err)
			}
			return
		}
		received := time.Now()

		addr := src.Addr().Unmap()
		if !c.isAllowed(addr) {
			c.Log.Debugf("Dropping packet from disallowed source %s", addr)
			continue
		}
		if c.Log.Level().Includes(telegraf.Trace) {
			c.Log.Tracef("Received %d bytes from %s: %s", n, addr, hex.EncodeToString(buf[:n]))
		}

		metrics, err := c.decode(addr.WithZone("").String(), buf[:n], received)
		for _, m := range metrics {
			acc.AddMetric(m)
		}
		if err != nil {
			acc.AddError(fmt.Errorf("decoding packet from %s failed: %w", addr, err))
		}
	}
}

func (c *CiscoURWB) isAllowed(addr netip.Addr) bool {
	if len(c.allowed) == 0 {
		return true
	}
	addr = addr.WithZone("")
	for _, prefix := range c.allowed {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// decode parses a telemetry packet. Metrics of successfully decoded TLVs are
// returned even if decoding other TLVs of the same packet failed.
func (c *CiscoURWB) decode(source string, buf []byte, timestamp time.Time) ([]telegraf.Metric, error) {
	if len(buf) < headerLen {
		return nil, fmt.Errorf("packet too short: %d bytes", len(buf))
	}
	if magic := binary.BigEndian.Uint32(buf[0:4]); magic != headerMagic {
		return nil, fmt.Errorf("invalid magic 0x%08X", magic)
	}
	records, err := splitTLVs(buf[headerLen:])
	if err != nil {
		return nil, err
	}

	p := &packet{
		tags:      map[string]string{"source": source},
		meshID:    binary.BigEndian.Uint32(buf[8:12]),
		timestamp: timestamp,
	}
	if p.meshID != 0 {
		p.tags["mesh_id"] = formatID(p.meshID)
	}
	if vehicleID := binary.BigEndian.Uint32(buf[12:16]); vehicleID != 0 {
		p.tags["vehicle_id"] = formatID(vehicleID)
	}
	if meshEndID := binary.BigEndian.Uint32(buf[16:20]); meshEndID != 0 {
		p.tags["meshend_id"] = formatID(meshEndID)
	}

	// The header timestamp is based on the device's internal clock and not on
	// wall-clock time, so use the receive time for all metrics instead.
	metrics := make([]telegraf.Metric, 0, len(records)+1)
	metrics = append(metrics, p.metric("urwb_packet", nil, map[string]any{
		"seq":       uint64(binary.BigEndian.Uint32(buf[20:24])),
		"flags":     uint64(binary.BigEndian.Uint32(buf[4:8])),
		"tlv_count": uint64(len(records)),
	}))

	var errs []error
	for _, r := range records {
		var m []telegraf.Metric
		var err error
		switch r.typ {
		case tlvFHCtrlVehicle:
			m, err = decodeFHCtrl(p, r.data, "vehicle")
		case tlvTitan:
			m, err = decodeTitan(p, r.data)
		case tlvEthThroughput:
			m, err = decodeEthThroughput(p, r.data)
		case tlvMultipath:
			m, err = decodeMultipath(p, r.data)
		case tlvFHCtrlVehicleMultiRadio:
			m, err = decodeFHCtrl(p, r.data, "vehicle_multi_radio")
		case tlvTxStatsMultiRadio:
			m, err = decodeTxStats(p, r.data)
		case tlvRxStatsMultiRadio:
			m, err = decodeRxStats(p, r.data)
		case tlvHandoffMultiRadio:
			m, err = decodeHandoff(p, r.data, false)
		case tlvAggrTrafficMultiRadio:
			m, err = decodeAggrTraffic(p, r.data)
		case tlvRadioConfigMultiRadio:
			m, err = decodeRadioConfig(p, r.data)
		case tlvMPOExt:
			m, err = decodeMPOExt(p, r.data)
		case tlvHandoffMultiRadioMPO:
			m, err = decodeHandoff(p, r.data, true)
		case tlvBlocklistMultiRadio:
			m, err = decodeBlocklist(p, r.data)
		default:
			c.logUnsupported(r.typ)
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid TLV 0x%03X: %w", r.typ, err))
			continue
		}
		metrics = append(metrics, m...)
	}

	return metrics, errors.Join(errs...)
}

func (c *CiscoURWB) logUnsupported(typ uint16) {
	if c.unsupported[typ] {
		return
	}
	c.unsupported[typ] = true
	c.Log.Debugf("Ignoring unsupported TLV type 0x%03X", typ)
}

func (p *packet) metric(name string, tags map[string]string, fields map[string]any) telegraf.Metric {
	t := make(map[string]string, len(p.tags)+len(tags))
	maps.Copy(t, p.tags)
	maps.Copy(t, tags)
	return metric.New(name, t, fields, p.timestamp)
}

func splitTLVs(buf []byte) ([]tlv, error) {
	records := make([]tlv, 0, 8)
	for len(buf) > 0 {
		if len(buf) < tlvHeaderLen {
			return nil, fmt.Errorf("truncated TLV header: %d bytes", len(buf))
		}
		// The upper four bits of type and length are reserved
		typ := binary.BigEndian.Uint16(buf[0:2]) & 0x0FFF
		length := int(binary.BigEndian.Uint16(buf[2:4]) & 0x0FFF)
		buf = buf[tlvHeaderLen:]
		if length > len(buf) {
			return nil, fmt.Errorf("length %d of TLV 0x%03X exceeds remaining %d bytes", length, typ, len(buf))
		}
		records = append(records, tlv{typ: typ, data: buf[:length]})
		buf = buf[length:]
	}
	return records, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.WithZone("")
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func init() {
	inputs.Add("cisco_urwb", func() telegraf.Input {
		return &CiscoURWB{}
	})
}

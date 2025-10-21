//go:generate ../../../tools/readme_config_includer/generator
package urwb

import (
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
)

const (
	pluginName           = "urwb"
	defaultServiceAddr   = "udp://:30000"
	defaultReadBuf       = 4 << 20  // 4 MiB
	defaultMaxPacketSize = 64 << 10 // 64 KiB

	headerMagic   uint32 = 0xF1CA0005
	baseHeaderLen        = 32
)

//go:embed sample.conf
var sampleConfig string

type listenPacketFunc func(ctx context.Context, network, address string) (net.PacketConn, error)

type packetEvent struct {
	data   []byte
	addr   net.Addr
	recvTS time.Time
}

const (
	tlVTypeFHCtrlVehicle        uint16 = 0x001
	tlVTypeTitan                uint16 = 0x00A
	tlVTypeEthThroughput        uint16 = 0x00D
	tlVTypeMultipath            uint16 = 0x01B
	tlVTypeFHCtrlVehicleMulti   uint16 = 0x01D
	tlVTypeTxStatsMulti         uint16 = 0x01E
	tlVTypeRxStatsMulti         uint16 = 0x01F
	tlVTypeHandoffTableMulti    uint16 = 0x021
	tlVTypeAggrTraffic          uint16 = 0x022
	tlVTypeRadioConfig          uint16 = 0x023
	tlVTypeMPOExt               uint16 = 0x024
	tlVTypeHandoffTableMultiMPO uint16 = 0x025
	tlVTypeBlocklistMultiRadio  uint16 = 0x026
)

const (
	fhctrlStateLen     = 34
	fhctrlEntryLen     = 18
	titanHeaderLen     = 22
	ethEntryLen        = 16
	txStatsEntryLen    = 28
	rxStatsEntryLen    = 22
	l3HandoffBaseLen   = 26
	aggrEthTrafficLen  = 8
	aggrWlanTrafficLen = 12
	radioConfigLen     = 20
	mpoExtEntryLen     = 38
	blocklistEntryLen  = 12
)

type tlvRecord struct {
	typ  uint16
	data []byte
}

type tlvDecoder func(ctx *decodeContext, data []byte) error

type decodeContext struct {
	plug       *URWB
	baseTags   map[string]string
	acc        telegraf.Accumulator
	packetTime time.Time
}

type URWB struct {
	ServiceAddress string   `toml:"service_address"`
	ReadBufferSize int      `toml:"read_buffer_size"`
	MaxPacketSize  int      `toml:"max_packet_size"`
	Workers        int      `toml:"workers"`
	DropInvalid    bool     `toml:"drop_invalid"`
	AllowedSources []string `toml:"allowed_sources"`

	Log telegraf.Logger `toml:"-"`

	conn   net.PacketConn
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	allowedNets []*net.IPNet
	listenFn    listenPacketFunc
	workerCh    chan packetEvent
	tlvDecoders map[uint16]tlvDecoder
}

var _ telegraf.ServiceInput = (*URWB)(nil)

func (*URWB) SampleConfig() string { return sampleConfig }
func (*URWB) Description() string  { return "Collect Cisco URWB telemetry over UDP (TLV-based)" }

func (u *URWB) Init() error {
	if u.ServiceAddress == "" {
		u.ServiceAddress = defaultServiceAddr
	}
	if u.ReadBufferSize <= 0 {
		u.ReadBufferSize = defaultReadBuf
	}
	if u.MaxPacketSize <= 0 {
		u.MaxPacketSize = defaultMaxPacketSize
	}
	if u.Workers < 0 {
		return fmt.Errorf("workers must be >= 0, got %d", u.Workers)
	}
	_, _, err := parseServiceAddress(u.ServiceAddress)
	if err != nil {
		return err
	}
	u.allowedNets = u.allowedNets[:0]
	if len(u.AllowedSources) > 0 {
		for _, raw := range u.AllowedSources {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" {
				continue
			}
			_, network, perr := net.ParseCIDR(trimmed)
			if perr != nil {
				return fmt.Errorf("invalid CIDR %q: %w", trimmed, perr)
			}
			u.allowedNets = append(u.allowedNets, network)
		}
	}
	if u.listenFn == nil {
		u.listenFn = func(ctx context.Context, network, address string) (net.PacketConn, error) {
			var lc net.ListenConfig
			return lc.ListenPacket(ctx, network, address)
		}
	}
	if len(u.tlvDecoders) == 0 {
		u.tlvDecoders = map[uint16]tlvDecoder{
			tlVTypeFHCtrlVehicle:        decodeFHCtrlVehicle,
			tlVTypeTitan:                decodeTitan,
			tlVTypeEthThroughput:        decodeEthThroughput,
			tlVTypeMultipath:            decodeMultipath,
			tlVTypeFHCtrlVehicleMulti:   decodeFHCtrlVehicleMulti,
			tlVTypeTxStatsMulti:         decodeTxStatsMulti,
			tlVTypeRxStatsMulti:         decodeRxStatsMulti,
			tlVTypeHandoffTableMulti:    decodeHandoffTable,
			tlVTypeAggrTraffic:          decodeAggrTraffic,
			tlVTypeRadioConfig:          decodeRadioConfig,
			tlVTypeMPOExt:               decodeMPOExt,
			tlVTypeHandoffTableMultiMPO: decodeHandoffTableMPO,
			tlVTypeBlocklistMultiRadio:  decodeBlocklist,
		}
	}
	return nil
}

func (u *URWB) Start(acc telegraf.Accumulator) error {
	if u.conn != nil {
		return errors.New("urwb input already running")
	}
	network, address, err := parseServiceAddress(u.ServiceAddress)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := u.listenFn(ctx, network, address)
	if err != nil {
		cancel()
		return err
	}
	if u.ReadBufferSize > 0 {
		if rb, ok := conn.(interface{ SetReadBuffer(int) error }); ok {
			if rerr := rb.SetReadBuffer(u.ReadBufferSize); rerr != nil && u.Log != nil {
				u.Log.Warnf("urwb: unable to set read buffer: %v", rerr)
			}
		}
	}
	u.ctx = ctx
	u.cancel = cancel
	u.conn = conn

	if u.Workers > 0 {
		u.workerCh = make(chan packetEvent, u.Workers*2+1)
		for i := 0; i < u.Workers; i++ {
			u.wg.Add(1)
			go u.workerLoop(acc)
		}
	} else {
		u.workerCh = nil
	}

	u.wg.Add(1)
	go u.readLoop(acc)

	if u.Log != nil {
		addr := conn.LocalAddr()
		u.Log.Infof("urwb: listening on %s://%s", network, addr.String())
	}

	return nil
}

func (u *URWB) Stop() {
	if u.cancel != nil {
		u.cancel()
	}
	if u.conn != nil {
		_ = u.conn.Close()
	}
	u.wg.Wait()
	u.conn = nil
	u.workerCh = nil
	u.ctx = nil
	u.cancel = nil
}

func (*URWB) Gather(telegraf.Accumulator) error { return nil }

func (u *URWB) readLoop(acc telegraf.Accumulator) {
	defer u.wg.Done()
	defer func() {
		if u.workerCh != nil {
			close(u.workerCh)
		}
	}()
	buf := make([]byte, u.MaxPacketSize)
	for {
		n, addr, err := u.conn.ReadFrom(buf)
		if err != nil {
			if u.ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			acc.AddError(fmt.Errorf("urwb read error: %w", err))
			continue
		}
		if n == 0 {
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		evt := packetEvent{data: payload, addr: addr, recvTS: time.Now()}
		if u.workerCh != nil {
			select {
			case <-u.ctx.Done():
				return
			case u.workerCh <- evt:
			}
		} else {
			u.processPacket(evt, acc)
		}
	}
}

func (u *URWB) workerLoop(acc telegraf.Accumulator) {
	defer u.wg.Done()
	for {
		select {
		case <-u.ctx.Done():
			return
		case evt, ok := <-u.workerCh:
			if !ok {
				return
			}
			u.processPacket(evt, acc)
		}
	}
}

func (u *URWB) processPacket(evt packetEvent, acc telegraf.Accumulator) {
	if !u.isAllowed(evt.addr) {
		return
	}
	hdr, payload, err := decodeHeader(evt.data)
	if err != nil {
		u.handleInvalid(fmt.Errorf("header decode failed: %w", err), acc)
		return
	}
	records, err := parseTLVs(payload)
	if err != nil {
		u.handleInvalid(fmt.Errorf("tlv parsing failed: %w", err), acc)
		return
	}
	tags := make(map[string]string, 4)
	if udpAddr, ok := evt.addr.(*net.UDPAddr); ok && udpAddr.IP != nil {
		tags["src_ip"] = udpAddr.IP.String()
	} else if evt.addr != nil {
		tags["src_ip"] = evt.addr.String()
	}
	if hdr.MeshID != 0 {
		tags["mesh_id"] = meshIDString(hdr.MeshID)
	}
	if hdr.VehicleID != 0 {
		tags["vehicle_id"] = meshIDString(hdr.VehicleID)
	}
	if hdr.MeshEndID != 0 {
		tags["meshend_id"] = meshIDString(hdr.MeshEndID)
	}
	// Use packet receive time as metric timestamp
	// The device timestamp is uptime-based, not wall-clock time
	pktTime := evt.recvTS
	ctx := decodeContext{
		plug:       u,
		baseTags:   tags,
		acc:        acc,
		packetTime: pktTime,
	}
	for _, record := range records {
		if decoder, ok := u.tlvDecoders[record.typ]; ok {
			if err := decoder(&ctx, record.data); err != nil {
				ctx.reportTLVError(record.typ, err)
			}
		} else if u.Log != nil {
			u.Log.Debugf("urwb: unsupported TLV type 0x%03X (%d bytes)", record.typ, len(record.data))
		}
	}
	fields := map[string]interface{}{
		"seq":       hdr.Sequence,
		"flags":     hdr.Flags,
		"tlv_count": len(records),
	}
	acc.AddFields("urwb_packet", fields, tags, pktTime)
}

func (u *URWB) handleInvalid(err error, acc telegraf.Accumulator) {
	if u.DropInvalid {
		if u.Log != nil {
			u.Log.Debugf("urwb: dropping packet: %v", err)
		}
		return
	}
	acc.AddError(err)
}

func (u *URWB) isAllowed(addr net.Addr) bool {
	if len(u.allowedNets) == 0 {
		return true
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return false
	}
	ip := udpAddr.IP
	if ip == nil {
		return false
	}
	for _, network := range u.allowedNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (ctx *decodeContext) mergeTags(extra map[string]string) map[string]string {
	tags := make(map[string]string, len(ctx.baseTags)+len(extra))
	for k, v := range ctx.baseTags {
		tags[k] = v
	}
	for k, v := range extra {
		if v == "" {
			continue
		}
		tags[k] = v
	}
	return tags
}

func (ctx *decodeContext) metricTime() time.Time {
	// Always use packet receive time for metric timestamps
	// Device timestamps are uptime-based, not wall-clock time
	return ctx.packetTime
}

func (ctx *decodeContext) emit(measurement string, fields map[string]interface{}, tags map[string]string) {
	if len(fields) == 0 {
		return
	}
	merged := ctx.mergeTags(tags)
	ctx.acc.AddFields(measurement, fields, merged, ctx.metricTime())
}

func (ctx *decodeContext) reportTLVError(tlvType uint16, err error) {
	if err == nil {
		return
	}
	wrapped := fmt.Errorf("tlv 0x%03X: %w", tlvType, err)
	if ctx.plug.Log != nil {
		ctx.plug.Log.Debugf("urwb: %v", wrapped)
	}
	if ctx.plug.DropInvalid {
		return
	}
	ctx.acc.AddError(wrapped)
}

type urwbHeader struct {
	Magic         uint32
	Flags         uint32
	MeshID        uint32
	VehicleID     uint32
	MeshEndID     uint32
	Sequence      uint32
	TimestampSec  uint32
	TimestampUsec uint32
}

func decodeHeader(packet []byte) (urwbHeader, []byte, error) {
	if len(packet) < baseHeaderLen {
		return urwbHeader{}, nil, fmt.Errorf("packet too short: %d", len(packet))
	}
	hdr := urwbHeader{
		Magic:         binary.BigEndian.Uint32(packet[0:4]),
		Flags:         binary.BigEndian.Uint32(packet[4:8]),
		MeshID:        binary.BigEndian.Uint32(packet[8:12]),
		VehicleID:     binary.BigEndian.Uint32(packet[12:16]),
		MeshEndID:     binary.BigEndian.Uint32(packet[16:20]),
		Sequence:      binary.BigEndian.Uint32(packet[20:24]),
		TimestampSec:  binary.BigEndian.Uint32(packet[24:28]),
		TimestampUsec: binary.BigEndian.Uint32(packet[28:32]),
	}
	if hdr.Magic != headerMagic {
		return urwbHeader{}, nil, fmt.Errorf("invalid magic 0x%08X", hdr.Magic)
	}
	return hdr, packet[baseHeaderLen:], nil
}

func parseTLVs(payload []byte) ([]tlvRecord, error) {
	records := make([]tlvRecord, 0, 8)
	offset := 0
	for offset+4 <= len(payload) {
		rawType := binary.BigEndian.Uint16(payload[offset : offset+2])
		rawLen := binary.BigEndian.Uint16(payload[offset+2 : offset+4])
		typ := rawType & 0x0FFF
		length := int(rawLen & 0x0FFF)
		offset += 4
		if offset+length > len(payload) {
			return records, fmt.Errorf("tlv 0x%03X length %d exceeds payload %d", typ, length, len(payload))
		}
		data := payload[offset : offset+length]
		records = append(records, tlvRecord{typ: typ, data: data})
		offset += length
	}
	if offset != len(payload) {
		return records, fmt.Errorf("payload has %d trailing bytes", len(payload)-offset)
	}
	return records, nil
}

func meshIDString(v uint32) string {
	// Use IP address format for URWB identifiers (mesh/vehicle/interface IDs)
	return ipString(v)
}

func ipString(v uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, v)
	return net.IP(ip).String()
}

func macString(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])
}

func parseServiceAddress(raw string) (string, string, error) {
	if raw == "" {
		return "", "", errors.New("service address required")
	}
	urlStr := raw
	if !strings.Contains(raw, "://") {
		urlStr = "udp://" + raw
	}
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return "", "", fmt.Errorf("invalid service address %q: %w", raw, err)
	}
	network := parsed.Scheme
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return "", "", fmt.Errorf("unsupported scheme %q", network)
	}
	host := parsed.Host
	if host == "" {
		host = parsed.Path
	}
	if host == "" {
		return "", "", fmt.Errorf("missing host/port in %q", raw)
	}
	return network, host, nil
}

func init() {
	inputs.Add(pluginName, func() telegraf.Input {
		return &URWB{
			ServiceAddress: defaultServiceAddr,
			ReadBufferSize: defaultReadBuf,
			MaxPacketSize:  defaultMaxPacketSize,
			DropInvalid:    true,
		}
	})
}

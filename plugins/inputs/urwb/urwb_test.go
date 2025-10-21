package urwb

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/testutil"
	"github.com/stretchr/testify/require"
)

type fakePacket struct {
	data []byte
	addr net.Addr
}

type fakePacketConn struct {
	packets chan fakePacket
	closed  chan struct{}
	mu      sync.Mutex
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{
		packets: make(chan fakePacket, 32),
		closed:  make(chan struct{}),
	}
}

func (f *fakePacketConn) inject(data []byte, addr net.Addr) {
	copyBuf := append([]byte(nil), data...)
	select {
	case <-f.closed:
		return
	default:
	}
	f.packets <- fakePacket{data: copyBuf, addr: addr}
}

func (f *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-f.closed:
		return 0, nil, net.ErrClosed
	case pkt, ok := <-f.packets:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(p, pkt.data)
		return n, pkt.addr, nil
	}
}

func (f *fakePacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("not implemented")
}

func (f *fakePacketConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	select {
	case <-f.closed:
		return nil
	default:
		close(f.closed)
		close(f.packets)
		return nil
	}
}

func (f *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 30000}
}

func (f *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

type pluginHarness struct {
	conn   *fakePacketConn
	acc    *testutil.Accumulator
	plugin *URWB
}

func newHarness(t *testing.T, configure func(*URWB)) *pluginHarness {
	t.Helper()
	conn := newFakePacketConn()
	p := &URWB{
		ServiceAddress: "udp://:0",
		Log:            &testutil.Logger{Quiet: true},
		listenFn: func(context.Context, string, string) (net.PacketConn, error) {
			return conn, nil
		},
	}
	if configure != nil {
		configure(p)
	}
	require.NoError(t, p.Init())
	acc := &testutil.Accumulator{}
	require.NoError(t, p.Start(acc))
	t.Cleanup(p.Stop)
	return &pluginHarness{conn: conn, acc: acc, plugin: p}
}

func waitForMetrics(t *testing.T, acc *testutil.Accumulator, expected int) {
	t.Helper()
	acc.Wait(expected)
	require.Eventually(t, func() bool {
		return int(acc.NMetrics()) >= expected
	}, time.Second, 10*time.Millisecond)
}

func metricsByName(acc *testutil.Accumulator, name string) []telegraf.Metric {
	all := acc.GetTelegrafMetrics()
	var out []telegraf.Metric
	for _, m := range all {
		if m.Name() == name {
			out = append(out, m)
		}
	}
	return out
}

func singleMetric(t *testing.T, acc *testutil.Accumulator, name string) telegraf.Metric {
	t.Helper()
	ms := metricsByName(acc, name)
	require.Len(t, ms, 1, "expected single metric %s", name)
	return ms[0]
}

type testTLV struct {
	typ  uint16
	data []byte
}

func makeTLV(typ uint16, data []byte) testTLV {
	return testTLV{typ: typ, data: data}
}

func buildPacket(seq, flags uint32, ts time.Time, meshID, vehicleID, meshEndID uint32, tlvs ...testTLV) []byte {
	header := make([]byte, baseHeaderLen)
	binary.BigEndian.PutUint32(header[0:4], headerMagic)
	binary.BigEndian.PutUint32(header[4:8], flags)
	binary.BigEndian.PutUint32(header[8:12], meshID)
	binary.BigEndian.PutUint32(header[12:16], vehicleID)
	binary.BigEndian.PutUint32(header[16:20], meshEndID)
	binary.BigEndian.PutUint32(header[20:24], seq)
	if !ts.IsZero() {
		binary.BigEndian.PutUint32(header[24:28], uint32(ts.Unix()))
		binary.BigEndian.PutUint32(header[28:32], uint32(ts.Nanosecond()/1000))
	}

	buf := append([]byte{}, header...)
	for _, tlv := range tlvs {
		length := len(tlv.data)
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:2], tlv.typ&0x0FFF)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(length)&0x0FFF)
		buf = append(buf, hdr...)
		buf = append(buf, tlv.data...)
	}
	return buf
}

func TestInitDefaults(t *testing.T) {
	p := &URWB{}
	require.NoError(t, p.Init())
	require.Equal(t, defaultServiceAddr, p.ServiceAddress)
	require.Equal(t, defaultReadBuf, p.ReadBufferSize)
	require.Equal(t, defaultMaxPacketSize, p.MaxPacketSize)
	require.NotNil(t, p.listenFn)
}

func TestInitValidatesConfig(t *testing.T) {
	p := &URWB{ServiceAddress: "tcp://:80"}
	require.Error(t, p.Init())

	p = &URWB{AllowedSources: []string{"bad"}}
	require.Error(t, p.Init())
}

func TestPacketProcessingInline(t *testing.T) {
	h := newHarness(t, nil)
	ts := time.Unix(1700000000, 123000000)
	tlv := sampleFHCtrlVehicleTLV()
	pkt := buildPacket(1, 3, ts, 0xAABBCCDD, 0x01020304, 0x05060708, tlv)
	start := time.Now()
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 12345})

	waitForMetrics(t, h.acc, 3)

	pktMetric := singleMetric(t, h.acc, "urwb_packet")
	require.WithinDuration(t, start, pktMetric.Time(), time.Second)
	require.Equal(t, "198.51.100.1", pktMetric.Tags()["src_ip"])
	require.Equal(t, "170.187.204.221", pktMetric.Tags()["mesh_id"])
	seq, ok := pktMetric.GetField("seq")
	require.True(t, ok)
	require.EqualValues(t, 1, seq)
	tlc, ok := pktMetric.GetField("tlv_count")
	require.True(t, ok)
	require.EqualValues(t, 1, tlc)
}

func TestPacketProcessingWorkers(t *testing.T) {
	h := newHarness(t, func(p *URWB) {
		p.Workers = 2
	})
	pkt := buildPacket(2, 7, time.Unix(1700000100, 0), 0, 0, 0,
		makeTLV(0x001, sampleFHCtrlStateWithEntries(0, false)))
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 12345})

	waitForMetrics(t, h.acc, 3)
	pktMetric := singleMetric(t, h.acc, "urwb_packet")
	tlc, ok := pktMetric.GetField("tlv_count")
	require.True(t, ok)
	require.EqualValues(t, 1, tlc)
}

func TestDropInvalidPacket(t *testing.T) {
	h := newHarness(t, func(p *URWB) {
		p.DropInvalid = true
	})
	pkt := buildPacket(1, 0, time.Unix(170, 0), 0, 0, 0)
	pkt[0] = 0x00
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1111})
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, uint64(0), h.acc.NMetrics())
	require.Len(t, h.acc.Errors, 0)
}

func TestReportInvalidPacketWhenConfigured(t *testing.T) {
	h := newHarness(t, func(p *URWB) {
		p.DropInvalid = false
	})
	pkt := buildPacket(1, 0, time.Unix(170, 0), 0, 0, 0)
	pkt[0] = 0x00
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1111})
	h.acc.WaitError(1)
	require.NotEmpty(t, h.acc.Errors)
}

func TestAllowedSources(t *testing.T) {
	h := newHarness(t, func(p *URWB) {
		p.AllowedSources = []string{"10.0.0.0/8"}
	})
	pkt := buildPacket(1, 0, time.Unix(170, 0), 1, 2, 3)
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1111})
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, uint64(0), h.acc.NMetrics())

	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("10.1.2.3"), Port: 2222})
	waitForMetrics(t, h.acc, 1)
	require.Equal(t, uint64(1), h.acc.NMetrics())
}

func TestFHCtrlVehicleDecoding(t *testing.T) {
	h := newHarness(t, nil)
	tlv := sampleFHCtrlVehicleTLV()
	pkt := buildPacket(10, 0, time.Unix(111, 0), 0, 0, 0, tlv)
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 5678})
	waitForMetrics(t, h.acc, 3)

	state := singleMetric(t, h.acc, "urwb_fhctrl_state")
	require.Equal(t, "vehicle", state.Tags()["variant"])
	require.Equal(t, "0.0.0.17", state.Tags()["current_sbr"])
	require.Equal(t, uint64(55), state.Fields()["current_sequence"])

	neighbors := metricsByName(h.acc, "urwb_fhctrl_neighbor")
	require.Len(t, neighbors, 1)
	neighbor := neighbors[0]
	require.Equal(t, "vehicle", neighbor.Tags()["variant"])
	require.Equal(t, "0.0.16.0", neighbor.Tags()["sbr_id"])
	require.Equal(t, uint64(36), neighbor.Fields()["channel_number"])
	require.Equal(t, uint64(80), neighbor.Fields()["channel_width_mhz"])
}

func TestFHCtrlVehicleMultiDecoding(t *testing.T) {
	h := newHarness(t, nil)
	tlv := sampleFHCtrlVehicleMultiTLV()
	pkt := buildPacket(11, 0, time.Unix(112, 0), 0, 0, 0, tlv)
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 5678})
	waitForMetrics(t, h.acc, 3)

	state := singleMetric(t, h.acc, "urwb_fhctrl_state")
	require.Equal(t, "vehicle_multi_radio", state.Tags()["variant"])
	require.Equal(t, "10.1.0.1", state.Tags()["current_sbr"])

	neighbor := singleMetric(t, h.acc, "urwb_fhctrl_neighbor")
	require.Equal(t, "vehicle_multi_radio", neighbor.Tags()["variant"])
	require.Equal(t, "10.2.0.2", neighbor.Tags()["mbr_id"])
}

func TestTitanDecoding(t *testing.T) {
	h := newHarness(t, nil)
	pkt := buildPacket(5, 0, time.Unix(200, 0), 0, 0, 0, sampleTitanTLV())
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("198.18.0.1"), Port: 9999})
	waitForMetrics(t, h.acc, 2)

	titan := singleMetric(t, h.acc, "urwb_titan_event")
	require.Equal(t, "mobile_failover", titan.Tags()["event_type"])
	require.Equal(t, uint64(42), titan.Fields()["event_count"])
	require.Equal(t, "0.0.190.239", titan.Fields()["master_id"])
}

func TestEthThroughputDecoding(t *testing.T) {
	h := newHarness(t, nil)
	pkt := buildPacket(6, 0, time.Unix(210, 0), 0, 0, 0, sampleEthThroughputTLV())
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("198.18.0.2"), Port: 9999})
	waitForMetrics(t, h.acc, 3)

	flows := metricsByName(h.acc, "urwb_eth_flow")
	require.Len(t, flows, 2)
	require.Equal(t, "tx", flows[0].Tags()["direction"])
	require.Equal(t, uint64(1234), flows[0].Fields()["throughput"])
	require.Equal(t, "rx", flows[1].Tags()["direction"])
}

func TestMultipathDecoding(t *testing.T) {
	h := newHarness(t, nil)
	pkt := buildPacket(7, 0, time.Unix(220, 0), 0, 0, 0, sampleMultipathTLV())
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("198.18.0.3"), Port: 9999})
	waitForMetrics(t, h.acc, 2)

	mp := singleMetric(t, h.acc, "urwb_multipath_route")
	require.Equal(t, "2", mp.Tags()["path_id"])
	require.Contains(t, mp.Fields()["peers"].(string), "0.0.170.170")
}

func TestTxStatsDecoding(t *testing.T) {
	h := newHarness(t, nil)
	pkt := buildPacket(8, 0, time.Unix(230, 0), 0, 0, 0, sampleTxStatsTLV())
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("198.18.0.4"), Port: 9999})
	waitForMetrics(t, h.acc, 2)

	tx := singleMetric(t, h.acc, "urwb_tx_stats")
	require.Equal(t, uint64(160), tx.Fields()["bandwidth_hint_mhz"])
	require.Equal(t, uint64(1600), tx.Fields()["guard_interval_ns"])
	require.Equal(t, uint64(50), tx.Fields()["packets_retried"])
}

func TestRxStatsDecoding(t *testing.T) {
	h := newHarness(t, nil)
	pkt := buildPacket(9, 0, time.Unix(240, 0), 0, 0, 0, sampleRxStatsTLV())
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("198.18.0.5"), Port: 9999})
	waitForMetrics(t, h.acc, 2)

	rx := singleMetric(t, h.acc, "urwb_rx_stats")
	require.Equal(t, int64(-45), rx.Fields()["rssi_dbm"])
	require.Equal(t, uint64(80), rx.Fields()["bandwidth_hint_mhz"])
	require.Equal(t, uint64(400), rx.Fields()["guard_interval_ns"])
}

func TestHandoffPrimaryDecoding(t *testing.T) {
	h := newHarness(t, nil)
	pkt := buildPacket(10, 0, time.Unix(250, 0), 0, 0, 0, sampleHandoffPrimaryTLV())
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("198.18.0.6"), Port: 9999})
	waitForMetrics(t, h.acc, 2)

	ho := singleMetric(t, h.acc, "urwb_handoff")
	require.Equal(t, "primary", ho.Tags()["variant"])
	require.Equal(t, uint64(99), ho.Fields()["handoff_seq"])
}

func TestHandoffSecondaryDecoding(t *testing.T) {
	h := newHarness(t, nil)
	pkt := buildPacket(11, 0, time.Unix(260, 0), 0, 0, 0, sampleHandoffSecondaryTLV())
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("198.18.0.7"), Port: 9999})
	waitForMetrics(t, h.acc, 2)

	ho := singleMetric(t, h.acc, "urwb_handoff")
	require.Equal(t, "secondary", ho.Tags()["variant"])
	require.Equal(t, uint64(3), ho.Fields()["path_id"])
}

func TestAggrTrafficDecoding(t *testing.T) {
	h := newHarness(t, nil)
	pkt := buildPacket(12, 0, time.Unix(270, 0), 0, 0, 0, sampleAggrTrafficTLV())
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("198.18.0.8"), Port: 9999})
	waitForMetrics(t, h.acc, 4)

	eth := singleMetric(t, h.acc, "urwb_aggr_eth")
	require.Equal(t, uint64(5000), eth.Fields()["rx_kbps"])
	wlan := metricsByName(h.acc, "urwb_aggr_wlan")
	require.Len(t, wlan, 2)
}

func TestRadioConfigDecoding(t *testing.T) {
	h := newHarness(t, nil)
	pkt := buildPacket(13, 0, time.Unix(280, 0), 0, 0, 0, sampleRadioConfigTLV())
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("198.18.0.9"), Port: 9999})
	waitForMetrics(t, h.acc, 3)

	radios := metricsByName(h.acc, "urwb_radio_config")
	require.Len(t, radios, 2)
	require.Equal(t, int64(30), radios[0].Fields()["tx_power_dbm"])
}

func TestMPOExtDecoding(t *testing.T) {
	h := newHarness(t, nil)
	pkt := buildPacket(14, 0, time.Unix(290, 0), 0, 0, 0, sampleMPOExtTLV())
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("198.18.0.10"), Port: 9999})
	waitForMetrics(t, h.acc, 2)

	mpo := singleMetric(t, h.acc, "urwb_mpo_ext")
	require.Equal(t, "AA:BB:CC:DD:EE:FF", mpo.Tags()["client_mac"])
}

func TestBlocklistDecoding(t *testing.T) {
	h := newHarness(t, nil)
	pkt := buildPacket(15, 0, time.Unix(300, 0), 0, 0, 0, sampleBlocklistTLV())
	h.conn.inject(pkt, &net.UDPAddr{IP: net.ParseIP("198.18.0.11"), Port: 9999})
	waitForMetrics(t, h.acc, 3)

	bl := metricsByName(h.acc, "urwb_blocklist")
	require.Len(t, bl, 2)
	require.Equal(t, "fastdrop", bl[0].Tags()["reason"])
	require.True(t, bl[1].Fields()["expiry_scale_seconds"].(bool))
}

func sampleFHCtrlStateWithEntries(flags uint32, idsAsIP bool) []byte {
	buf := make([]byte, fhctrlStateLen+fhctrlEntryLen)
	binary.BigEndian.PutUint32(buf[0:4], 0x00000011)
	binary.BigEndian.PutUint32(buf[4:8], 0x00000022)
	binary.BigEndian.PutUint32(buf[8:12], 55)
	binary.BigEndian.PutUint32(buf[12:16], 10)
	binary.BigEndian.PutUint32(buf[16:20], 500000)
	buf[20] = 4
	buf[21] = 0x80
	binary.BigEndian.PutUint32(buf[22:26], 1234)
	binary.BigEndian.PutUint32(buf[26:30], 0x00140002)
	binary.BigEndian.PutUint16(buf[30:32], 0x000F)
	binary.BigEndian.PutUint16(buf[32:34], 0x00FF)

	offset := fhctrlStateLen
	binary.BigEndian.PutUint32(buf[offset:offset+4], 0x00001000)
	binary.BigEndian.PutUint32(buf[offset+4:offset+8], 0x00002000)
	binary.BigEndian.PutUint32(buf[offset+8:offset+12], 0x000A0003)
	binary.BigEndian.PutUint16(buf[offset+12:offset+14], 0x6024)
	binary.BigEndian.PutUint16(buf[offset+14:offset+16], 77)
	buf[offset+16] = 0xD6
	buf[offset+17] = 0x31
	return buf
}

func sampleFHCtrlVehicleTLV() testTLV {
	return makeTLV(tlVTypeFHCtrlVehicle, sampleFHCtrlStateWithEntries(0, false))
}

func sampleFHCtrlVehicleMultiTLV() testTLV {
	buf := sampleFHCtrlStateWithEntries(0, true)
	binary.BigEndian.PutUint32(buf[0:4], 0x0A010001)
	binary.BigEndian.PutUint32(buf[4:8], 0x0A020002)
	binary.BigEndian.PutUint32(buf[fhctrlStateLen:fhctrlStateLen+4], 0x0A030003)
	binary.BigEndian.PutUint32(buf[fhctrlStateLen+4:fhctrlStateLen+8], 0x0A020002)
	return makeTLV(tlVTypeFHCtrlVehicleMulti, buf)
}

func sampleTitanTLV() testTLV {
	buf := make([]byte, titanHeaderLen)
	buf[0] = 1
	buf[1] = 0x10 | 0x04
	binary.BigEndian.PutUint32(buf[2:6], 300)
	binary.BigEndian.PutUint32(buf[6:10], 1000)
	binary.BigEndian.PutUint32(buf[10:14], 42)
	binary.BigEndian.PutUint32(buf[14:18], 0x0000BEEF)
	binary.BigEndian.PutUint32(buf[18:22], 0x0000FACE)
	return makeTLV(tlVTypeTitan, buf)
}

func sampleEthThroughputTLV() testTLV {
	buf := make([]byte, 2+2*ethEntryLen)
	binary.BigEndian.PutUint16(buf[0:2], 1)
	offset := 2
	binary.BigEndian.PutUint32(buf[offset:offset+4], 0x0A000001)
	binary.BigEndian.PutUint32(buf[offset+4:offset+8], 0x0A000002)
	binary.BigEndian.PutUint32(buf[offset+8:offset+12], 1234)
	binary.BigEndian.PutUint32(buf[offset+12:offset+16], 100)
	offset += ethEntryLen
	binary.BigEndian.PutUint32(buf[offset:offset+4], 0x0A000002)
	binary.BigEndian.PutUint32(buf[offset+4:offset+8], 0x0A000001)
	binary.BigEndian.PutUint32(buf[offset+8:offset+12], 9876)
	binary.BigEndian.PutUint32(buf[offset+12:offset+16], 90)
	return makeTLV(tlVTypeEthThroughput, buf)
}

func sampleMultipathTLV() testTLV {
	buf := make([]byte, 4+3*4)
	buf[0] = 0x42
	buf[1] = 3
	binary.BigEndian.PutUint16(buf[2:4], 12)
	binary.BigEndian.PutUint32(buf[4:8], 0x0000AAAA)
	binary.BigEndian.PutUint32(buf[8:12], 0x0000BBBB)
	binary.BigEndian.PutUint32(buf[12:16], 0x0000CCCC)
	return makeTLV(tlVTypeMultipath, buf)
}

func sampleTxStatsTLV() testTLV {
	buf := make([]byte, txStatsEntryLen)
	binary.BigEndian.PutUint32(buf[0:4], 0x0A000001)
	binary.BigEndian.PutUint32(buf[4:8], 0x0A000002)
	binary.BigEndian.PutUint32(buf[8:12], 1000)
	binary.BigEndian.PutUint32(buf[12:16], 50)
	binary.BigEndian.PutUint32(buf[16:20], 10)
	binary.BigEndian.PutUint32(buf[20:24], 64000)
	binary.BigEndian.PutUint16(buf[24:26], 200)
	buf[26] = 0x08 | 0x20 | 0x80
	buf[27] = 7
	return makeTLV(tlVTypeTxStatsMulti, buf)
}

func sampleRxStatsTLV() testTLV {
	buf := make([]byte, rxStatsEntryLen)
	binary.BigEndian.PutUint32(buf[0:4], 0x0A000002)
	binary.BigEndian.PutUint32(buf[4:8], 0x0A000001)
	binary.BigEndian.PutUint32(buf[8:12], 2000)
	binary.BigEndian.PutUint32(buf[12:16], 128000)
	buf[16] = 0xD3
	buf[17] = 9
	buf[18] = 0x04 | 0x40
	binary.BigEndian.PutUint16(buf[20:22], 150)
	return makeTLV(tlVTypeRxStatsMulti, buf)
}

func sampleHandoffPrimaryTLV() testTLV {
	buf := make([]byte, l3HandoffBaseLen+2*4)
	binary.BigEndian.PutUint32(buf[0:4], 0x0A000010)
	binary.BigEndian.PutUint32(buf[4:8], 0x0A000011)
	binary.BigEndian.PutUint32(buf[8:12], 0x0000DEAD)
	binary.BigEndian.PutUint32(buf[12:16], 0x0000F00D)
	binary.BigEndian.PutUint32(buf[16:20], 99)
	binary.BigEndian.PutUint32(buf[20:24], 321)
	buf[24] = 0
	buf[25] = 2
	binary.BigEndian.PutUint32(buf[26:30], 0x00001234)
	binary.BigEndian.PutUint32(buf[30:34], 0x00005678)
	return makeTLV(tlVTypeHandoffTableMulti, buf)
}

func sampleHandoffSecondaryTLV() testTLV {
	buf := make([]byte, l3HandoffBaseLen+2*4)
	binary.BigEndian.PutUint32(buf[0:4], 0x0A000020)
	binary.BigEndian.PutUint32(buf[4:8], 0x0A000021)
	binary.BigEndian.PutUint32(buf[8:12], 0x0000DEAD)
	binary.BigEndian.PutUint32(buf[12:16], 0x0000FEED)
	binary.BigEndian.PutUint32(buf[16:20], 101)
	binary.BigEndian.PutUint32(buf[20:24], 654)
	buf[24] = 0x03
	buf[25] = 1
	binary.BigEndian.PutUint32(buf[26:30], 0x0000AAAA)
	return makeTLV(tlVTypeHandoffTableMultiMPO, buf)
}

func sampleAggrTrafficTLV() testTLV {
	buf := make([]byte, aggrEthTrafficLen+2*aggrWlanTrafficLen)
	binary.BigEndian.PutUint32(buf[0:4], 5000)
	binary.BigEndian.PutUint32(buf[4:8], 7000)
	offset := aggrEthTrafficLen
	binary.BigEndian.PutUint32(buf[offset:offset+4], 1000)
	binary.BigEndian.PutUint32(buf[offset+4:offset+8], 2000)
	binary.BigEndian.PutUint32(buf[offset+8:offset+12], 3000)
	offset += aggrWlanTrafficLen
	binary.BigEndian.PutUint32(buf[offset:offset+4], 1100)
	binary.BigEndian.PutUint32(buf[offset+4:offset+8], 2200)
	binary.BigEndian.PutUint32(buf[offset+8:offset+12], 3300)
	return makeTLV(tlVTypeAggrTraffic, buf)
}

func sampleRadioConfigTLV() testTLV {
	buf := make([]byte, 2*radioConfigLen)
	// radio 0
	buf[0] = 0
	buf[1] = 0x10 | 0x01
	copy(buf[2:8], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	buf[8] = 0x20
	buf[9] = byte(int8(30))
	binary.BigEndian.PutUint16(buf[10:12], 20)
	binary.BigEndian.PutUint32(buf[12:16], 5180)
	binary.BigEndian.PutUint32(buf[16:20], 0)
	// radio 1
	offset := radioConfigLen
	buf[offset] = 1
	buf[offset+1] = 0x30 | 0x02
	copy(buf[offset+2:offset+8], []byte{0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6})
	buf[offset+8] = 0x60
	buf[offset+9] = byte(int8(18))
	binary.BigEndian.PutUint16(buf[offset+10:offset+12], 10)
	binary.BigEndian.PutUint32(buf[offset+12:offset+16], 2412)
	binary.BigEndian.PutUint32(buf[offset+16:offset+20], 2437)
	return makeTLV(tlVTypeRadioConfig, buf)
}

func sampleMPOExtTLV() testTLV {
	buf := make([]byte, mpoExtEntryLen)
	copy(buf[0:6], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	binary.BigEndian.PutUint32(buf[6:10], 100)
	binary.BigEndian.PutUint32(buf[10:14], 80)
	binary.BigEndian.PutUint32(buf[14:18], 70)
	binary.BigEndian.PutUint32(buf[18:22], 3)
	binary.BigEndian.PutUint32(buf[22:26], 60)
	binary.BigEndian.PutUint32(buf[26:30], 2)
	binary.BigEndian.PutUint32(buf[30:34], 1)
	binary.BigEndian.PutUint32(buf[34:38], 5)
	return makeTLV(tlVTypeMPOExt, buf)
}

func sampleBlocklistTLV() testTLV {
	buf := make([]byte, 2*blocklistEntryLen)
	binary.BigEndian.PutUint32(buf[0:4], 0x0A000001)
	binary.BigEndian.PutUint32(buf[4:8], 0x0A000002)
	binary.BigEndian.PutUint32(buf[8:12], (uint32(1)<<24)|(20<<0))
	offset := blocklistEntryLen
	binary.BigEndian.PutUint32(buf[offset:offset+4], 0)
	binary.BigEndian.PutUint32(buf[offset+4:offset+8], 0x0A000003)
	binary.BigEndian.PutUint32(buf[offset+8:offset+12], (uint32(2)<<24)|(1<<23)|100)
	return makeTLV(tlVTypeBlocklistMultiRadio, buf)
}

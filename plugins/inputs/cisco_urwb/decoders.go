package cisco_urwb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/influxdata/telegraf"
)

// TLV types as defined in the URWB Telemetry Protocol specification
const (
	tlvFHCtrlVehicle           = 0x001
	tlvTitan                   = 0x00A
	tlvEthThroughput           = 0x00D
	tlvMultipath               = 0x01B
	tlvFHCtrlVehicleMultiRadio = 0x01D
	tlvTxStatsMultiRadio       = 0x01E
	tlvRxStatsMultiRadio       = 0x01F
	tlvHandoffMultiRadio       = 0x021
	tlvAggrTrafficMultiRadio   = 0x022
	tlvRadioConfigMultiRadio   = 0x023
	tlvMPOExt                  = 0x024
	tlvHandoffMultiRadioMPO    = 0x025
	tlvBlocklistMultiRadio     = 0x026
)

// Sizes of the fixed-length structures in bytes
const (
	fhctrlStateLen     = 34
	fhctrlEntryLen     = 18
	titanLen           = 22
	ethThroughputLen   = 2
	ethEntryLen        = 16
	multipathRouteLen  = 4
	txStatsLen         = 28
	rxStatsLen         = 22
	handoffLen         = 26
	aggrEthTrafficLen  = 8
	aggrWlanTrafficLen = 12
	radioConfigLen     = 20
	mpoExtLen          = 38
	blocklistLen       = 12
)

var titanEventTypes = map[uint8]string{
	0: "topology_change",
	1: "mobile_failover",
	2: "mesh_end_failover",
	4: "global_gateway_failover",
}

var titanEventReasons = map[uint8]string{
	0: "unspecified",
	1: "link_failure",
	2: "node_failure",
	4: "recovery",
}

var titanEventDomains = map[uint8]string{
	0: "local",
	1: "remote",
}

var radioModes = map[uint8]string{
	0: "unused",
	1: "fluidity",
	2: "fixed_infrastructure",
	3: "fluidmax",
	4: "bridge",
}

var blocklistReasons = map[uint8]string{
	0: "unspecified",
	1: "fastdrop",
	2: "poleban",
	3: "rssiban",
	4: "handoff_fail",
	5: "handoff_reject",
}

func decodeFHCtrl(p *packet, data []byte, variant string) ([]telegraf.Metric, error) {
	if len(data) < fhctrlStateLen {
		return nil, fmt.Errorf("state too short: %d bytes", len(data))
	}
	entries := data[fhctrlStateLen:]
	if err := checkAligned(entries, fhctrlEntryLen); err != nil {
		return nil, fmt.Errorf("neighbor entries: %w", err)
	}
	metrics := make([]telegraf.Metric, 0, 1+len(entries)/fhctrlEntryLen)

	state := data[:fhctrlStateLen]
	sbr := binary.BigEndian.Uint32(state[0:4])
	mbr := binary.BigEndian.Uint32(state[4:8])
	handoffFlags := state[21]
	handoffAge := binary.BigEndian.Uint32(state[22:26])
	dop := binary.BigEndian.Uint32(state[26:30])
	flags := binary.BigEndian.Uint16(state[30:32])

	tags := map[string]string{"variant": variant}
	if sbr != 0 {
		tags["current_sbr"] = formatID(sbr)
	}
	if mbr != 0 {
		tags["current_mbr"] = formatID(mbr)
	}
	fields := map[string]any{
		"current_sequence":    uint64(binary.BigEndian.Uint32(state[8:12])),
		"handoff_retries":     uint64(state[20]),
		"handoff_pending":     handoffFlags&0x40 != 0,
		"handoff_failed":      handoffFlags&0x80 != 0,
		"dop_value":           uint64(dop & 0xFFFF),
		"dop_color":           uint64(dop >> 16),
		"flags_raw":           uint64(flags),
		"flag_wireless_relay": flags&0x0001 != 0,
		"flag_can_accept":     flags&0x0002 != 0,
		"flag_is_critical":    flags&0x0004 != 0,
		"flag_freq_scan":      flags&0x0008 != 0,
		"inhibit_mask":        uint64(binary.BigEndian.Uint16(state[32:34])),
	}
	// An age of 0xFFFFFFFF marks the value as not available
	if handoffAge != 0xFFFFFFFF {
		fields["handoff_age_ms"] = uint64(handoffAge)
	}
	metrics = append(metrics, p.metric("urwb_fhctrl_state", tags, fields))

	for entry := range slices.Chunk(entries, fhctrlEntryLen) {
		entryDOP := binary.BigEndian.Uint32(entry[8:12])
		channelInfo := binary.BigEndian.Uint16(entry[12:14])
		widthCode := channelInfo >> 12
		entryFlags := entry[17]

		entryTags := map[string]string{
			"variant": variant,
			"sbr":     formatID(binary.BigEndian.Uint32(entry[0:4])),
			"mbr":     formatID(binary.BigEndian.Uint32(entry[4:8])),
		}
		entryFields := map[string]any{
			"channel_number":     uint64(channelInfo & 0x00FF),
			"channel_width_code": uint64(widthCode),
			"dop_value":          uint64(entryDOP & 0xFFFF),
			"dop_color":          uint64(entryDOP >> 16),
			"age_ms":             uint64(binary.BigEndian.Uint16(entry[14:16])),
			"rssi_dbm":           int64(int8(entry[16])),
			"flags_raw":          uint64(entryFlags),
			"scanning":           entryFlags&0x01 != 0,
			"active_link":        entryFlags&0x10 != 0,
			"link_id":            uint64(entryFlags >> 5),
		}
		if width := channelWidthMHz(widthCode); width > 0 {
			entryFields["channel_width_mhz"] = width
		}
		metrics = append(metrics, p.metric("urwb_fhctrl_neighbor", entryTags, entryFields))
	}

	return metrics, nil
}

func decodeTitan(p *packet, data []byte) ([]telegraf.Metric, error) {
	if len(data) < titanLen {
		return nil, fmt.Errorf("too short: %d bytes", len(data))
	}
	eventType := data[0] & 0x0F
	eventReason := data[1] & 0x0F
	eventDomain := (data[1] >> 4) & 0x01
	master := binary.BigEndian.Uint32(data[14:18])
	backup := binary.BigEndian.Uint32(data[18:22])

	tags := map[string]string{
		"event_type":   lookup(titanEventTypes, eventType),
		"event_reason": lookup(titanEventReasons, eventReason),
		"event_domain": lookup(titanEventDomains, eventDomain),
	}
	fields := map[string]any{
		"event_type_code":   uint64(eventType),
		"event_reason_code": uint64(eventReason),
		"event_domain_code": uint64(eventDomain),
		"event_count":       uint64(binary.BigEndian.Uint32(data[10:14])),
	}
	if master != 0 {
		fields["master_id"] = formatID(master)
	}
	if backup != 0 {
		fields["backup_id"] = formatID(backup)
	}

	return []telegraf.Metric{p.metric("urwb_titan_event", tags, fields)}, nil
}

func decodeEthThroughput(p *packet, data []byte) ([]telegraf.Metric, error) {
	if len(data) < ethThroughputLen {
		return nil, fmt.Errorf("too short: %d bytes", len(data))
	}
	numTX := int(binary.BigEndian.Uint16(data[0:2]))
	entries := data[ethThroughputLen:]
	if err := checkAligned(entries, ethEntryLen); err != nil {
		return nil, err
	}
	n := len(entries) / ethEntryLen
	if numTX > n {
		return nil, fmt.Errorf("number of TX entries %d exceeds total number of entries %d", numTX, n)
	}

	// The first numTX entries are TX entries followed by the RX entries
	metrics := make([]telegraf.Metric, 0, n)
	for i := range n {
		entry := entries[i*ethEntryLen : (i+1)*ethEntryLen]
		direction := "rx"
		if i < numTX {
			direction = "tx"
		}
		tags := map[string]string{
			"direction":   direction,
			"src_address": formatID(binary.BigEndian.Uint32(entry[0:4])),
			"dst_address": formatID(binary.BigEndian.Uint32(entry[4:8])),
		}
		fields := map[string]any{
			"throughput": uint64(binary.BigEndian.Uint32(entry[8:12])),
			"packets":    uint64(binary.BigEndian.Uint32(entry[12:16])),
		}
		metrics = append(metrics, p.metric("urwb_eth_flow", tags, fields))
	}

	return metrics, nil
}

func decodeMultipath(p *packet, data []byte) ([]telegraf.Metric, error) {
	// Peers only contain the lowest three octets of the mesh ID
	self := p.meshID & 0x00FFFFFF

	metrics := make([]telegraf.Metric, 0, len(data)/(multipathRouteLen+4))
	for len(data) > 0 {
		if len(data) < multipathRouteLen {
			return nil, fmt.Errorf("truncated route: %d bytes", len(data))
		}
		flags := data[0]
		numPeers := int(data[1])
		age := binary.BigEndian.Uint16(data[2:4])
		data = data[multipathRouteLen:]
		if numPeers == 0 {
			return nil, errors.New("route without peers")
		}
		if len(data) < 4*numPeers {
			return nil, fmt.Errorf("route with %d peers truncated: %d bytes", numPeers, len(data))
		}

		peers := make([]uint32, 0, numPeers)
		ids := make([]string, 0, numPeers)
		interfaces := make([]string, 0, numPeers)
		for raw := range slices.Chunk(data[:4*numPeers], 4) {
			v := binary.BigEndian.Uint32(raw)
			peers = append(peers, v&0x00FFFFFF)
			ids = append(ids, formatID(v&0x00FFFFFF))
			interfaces = append(interfaces, fmt.Sprintf("%d:%d", (v>>24)&0x0F, v>>28))
		}
		data = data[4*numPeers:]

		tags := map[string]string{
			"destination": formatID(routeDestination(peers, self)),
		}
		fields := map[string]any{
			"flags_raw":           uint64(flags),
			"mobility_lsp":        flags&0x01 != 0,
			"destination_gateway": flags&0x04 != 0,
			"num_peers":           uint64(numPeers),
			"peers":               strings.Join(ids, ","),
			"peer_interfaces":     strings.Join(interfaces, ","),
		}
		// A route with a single peer is an empty route notifying about the
		// removal of all routes to that peer. The path ID and age are not
		// meaningful in this case.
		if numPeers > 1 {
			tags["path_id"] = strconv.Itoa(int(flags >> 5))
			fields["age_seconds"] = uint64(age)
		}
		metrics = append(metrics, p.metric("urwb_multipath_route", tags, fields))
	}

	return metrics, nil
}

// routeDestination returns the end of the route that is not the reporting
// unit itself, as the specification does not define the order of the peers.
// The last peer is used if neither end matches the reporting unit.
func routeDestination(peers []uint32, self uint32) uint32 {
	last := peers[len(peers)-1]
	if last == self && len(peers) > 1 {
		return peers[0]
	}
	return last
}

func decodeTxStats(p *packet, data []byte) ([]telegraf.Metric, error) {
	if err := checkAligned(data, txStatsLen); err != nil {
		return nil, err
	}

	metrics := make([]telegraf.Metric, 0, len(data)/txStatsLen)
	for entry := range slices.Chunk(data, txStatsLen) {
		tags := map[string]string{
			"src_interface": formatID(binary.BigEndian.Uint32(entry[0:4])),
			"dst_interface": formatID(binary.BigEndian.Uint32(entry[4:8])),
		}
		fields := map[string]any{
			"packets_sent":    uint64(binary.BigEndian.Uint32(entry[8:12])),
			"packets_retried": uint64(binary.BigEndian.Uint32(entry[12:16])),
			"packets_failed":  uint64(binary.BigEndian.Uint32(entry[16:20])),
			"bytes_sent":      uint64(binary.BigEndian.Uint32(entry[20:24])),
			"age_ms":          uint64(binary.BigEndian.Uint16(entry[24:26])),
			"mcs":             uint64(entry[27]),
		}
		addRateFields(fields, entry[26])
		metrics = append(metrics, p.metric("urwb_tx_stats", tags, fields))
	}

	return metrics, nil
}

func decodeRxStats(p *packet, data []byte) ([]telegraf.Metric, error) {
	if err := checkAligned(data, rxStatsLen); err != nil {
		return nil, err
	}

	metrics := make([]telegraf.Metric, 0, len(data)/rxStatsLen)
	for entry := range slices.Chunk(data, rxStatsLen) {
		tags := map[string]string{
			"src_interface": formatID(binary.BigEndian.Uint32(entry[0:4])),
			"dst_interface": formatID(binary.BigEndian.Uint32(entry[4:8])),
		}
		fields := map[string]any{
			"packets_received": uint64(binary.BigEndian.Uint32(entry[8:12])),
			"bytes_received":   uint64(binary.BigEndian.Uint32(entry[12:16])),
			"rssi_dbm":         int64(int8(entry[16])),
			"mcs":              uint64(entry[17]),
			"age_ms":           uint64(binary.BigEndian.Uint16(entry[20:22])),
		}
		addRateFields(fields, entry[18])
		metrics = append(metrics, p.metric("urwb_rx_stats", tags, fields))
	}

	return metrics, nil
}

// addRateFields decodes the TX_FLAGS and RX_FLAGS of the statistics TLVs
func addRateFields(fields map[string]any, flags byte) {
	bandwidth := uint64(20)
	switch {
	case flags&0x08 != 0:
		bandwidth = 160
	case flags&0x04 != 0:
		bandwidth = 80
	case flags&0x01 != 0:
		bandwidth = 40
	}
	guardInterval := flags >> 6

	fields["flags_raw"] = uint64(flags)
	fields["bandwidth_hint_mhz"] = bandwidth
	fields["mcs_type"] = uint64((flags >> 4) & 0x03)
	fields["guard_interval_code"] = uint64(guardInterval)
	fields["guard_interval_ns"] = [...]uint64{800, 400, 1600, 3200}[guardInterval]
}

func decodeHandoff(p *packet, data []byte, mpo bool) ([]telegraf.Metric, error) {
	metrics := make([]telegraf.Metric, 0, len(data)/handoffLen)
	for len(data) > 0 {
		if len(data) < handoffLen {
			return nil, fmt.Errorf("truncated entry: %d bytes", len(data))
		}
		entry := data[:handoffLen]
		numUnits := int(entry[25])
		data = data[handoffLen:]
		if len(data) < 4*numUnits {
			return nil, fmt.Errorf("entry with %d units truncated: %d bytes", numUnits, len(data))
		}
		units := make([]string, 0, numUnits)
		for raw := range slices.Chunk(data[:4*numUnits], 4) {
			units = append(units, formatID(binary.BigEndian.Uint32(raw)))
		}
		data = data[4*numUnits:]

		// The primary path always has ID zero, secondary paths are only
		// reported by the MPO variant of the TLV.
		variant, pathID := "primary", 0
		if mpo {
			variant, pathID = "secondary", int(entry[24]&0x07)
		}
		tags := map[string]string{
			"variant": variant,
			"path_id": strconv.Itoa(pathID),
			"sbr":     formatID(binary.BigEndian.Uint32(entry[0:4])),
			"mbr":     formatID(binary.BigEndian.Uint32(entry[4:8])),
		}
		fields := map[string]any{
			"master_id":         formatID(binary.BigEndian.Uint32(entry[8:12])),
			"remote_vehicle_id": formatID(binary.BigEndian.Uint32(entry[12:16])),
			"handoff_seq":       uint64(binary.BigEndian.Uint32(entry[16:20])),
			"age_ms":            uint64(binary.BigEndian.Uint32(entry[20:24])),
			"num_units":         uint64(numUnits),
		}
		if numUnits > 0 {
			fields["unit_ids"] = strings.Join(units, ",")
		}
		metrics = append(metrics, p.metric("urwb_handoff", tags, fields))
	}

	return metrics, nil
}

func decodeAggrTraffic(p *packet, data []byte) ([]telegraf.Metric, error) {
	if len(data) < aggrEthTrafficLen {
		return nil, fmt.Errorf("too short: %d bytes", len(data))
	}
	wlan := data[aggrEthTrafficLen:]
	if err := checkAligned(wlan, aggrWlanTrafficLen); err != nil {
		return nil, fmt.Errorf("wireless entries: %w", err)
	}
	n := len(wlan) / aggrWlanTrafficLen

	metrics := make([]telegraf.Metric, 0, 1+n)
	metrics = append(metrics, p.metric("urwb_aggr_eth", nil, map[string]any{
		"rx_kbps": uint64(binary.BigEndian.Uint32(data[0:4])),
		"tx_kbps": uint64(binary.BigEndian.Uint32(data[4:8])),
	}))
	for i := range n {
		entry := wlan[i*aggrWlanTrafficLen : (i+1)*aggrWlanTrafficLen]
		tags := map[string]string{"iface_index": strconv.Itoa(i)}
		fields := map[string]any{
			"rx_kbps":            uint64(binary.BigEndian.Uint32(entry[0:4])),
			"tx_kbps":            uint64(binary.BigEndian.Uint32(entry[4:8])),
			"available_capacity": uint64(binary.BigEndian.Uint32(entry[8:12])),
		}
		metrics = append(metrics, p.metric("urwb_aggr_wlan", tags, fields))
	}

	return metrics, nil
}

func decodeRadioConfig(p *packet, data []byte) ([]telegraf.Metric, error) {
	if err := checkAligned(data, radioConfigLen); err != nil {
		return nil, err
	}

	metrics := make([]telegraf.Metric, 0, len(data)/radioConfigLen)
	for entry := range slices.Chunk(data, radioConfigLen) {
		mode := entry[1]
		status := entry[8]
		secondaryFrequency := binary.BigEndian.Uint32(entry[16:20]) & 0x1FFFF

		tags := map[string]string{
			"radio_id": strconv.Itoa(int(entry[0] & 0x03)),
			"mode":     lookup(radioModes, mode&0x07),
		}
		fields := map[string]any{
			"mac_address":           net.HardwareAddr(entry[2:8]).String(),
			"mode_code":             uint64(mode & 0x07),
			"interface_enabled":     mode&0x10 != 0,
			"he_enabled":            mode&0x20 != 0,
			"tdma_mode":             status&0x20 != 0,
			"scanning":              status&0x40 != 0,
			"tx_disabled":           status&0x80 != 0,
			"tx_power_dbm":          int64(int8(entry[9])),
			"channel_width_mhz":     uint64(binary.BigEndian.Uint16(entry[10:12]) & 0x0FFF),
			"primary_frequency_mhz": uint64(binary.BigEndian.Uint32(entry[12:16]) & 0x1FFFF),
		}
		if secondaryFrequency != 0 {
			fields["secondary_frequency_mhz"] = uint64(secondaryFrequency)
		}
		metrics = append(metrics, p.metric("urwb_radio_config", tags, fields))
	}

	return metrics, nil
}

func decodeMPOExt(p *packet, data []byte) ([]telegraf.Metric, error) {
	if err := checkAligned(data, mpoExtLen); err != nil {
		return nil, err
	}

	metrics := make([]telegraf.Metric, 0, len(data)/mpoExtLen)
	for entry := range slices.Chunk(data, mpoExtLen) {
		tags := map[string]string{
			"client_mac": net.HardwareAddr(entry[0:6]).String(),
		}
		fields := map[string]any{
			"tx_primary":          uint64(binary.BigEndian.Uint32(entry[6:10])),
			"tx_secondary":        uint64(binary.BigEndian.Uint32(entry[10:14])),
			"rx_primary_accept":   uint64(binary.BigEndian.Uint32(entry[14:18])),
			"rx_primary_drop":     uint64(binary.BigEndian.Uint32(entry[18:22])),
			"rx_secondary_accept": uint64(binary.BigEndian.Uint32(entry[22:26])),
			"rx_secondary_drop":   uint64(binary.BigEndian.Uint32(entry[26:30])),
			"lost_both":           uint64(binary.BigEndian.Uint32(entry[30:34])),
			"lost_primary_only":   uint64(binary.BigEndian.Uint32(entry[34:38])),
		}
		metrics = append(metrics, p.metric("urwb_mpo_ext", tags, fields))
	}

	return metrics, nil
}

func decodeBlocklist(p *packet, data []byte) ([]telegraf.Metric, error) {
	if err := checkAligned(data, blocklistLen); err != nil {
		return nil, err
	}

	metrics := make([]telegraf.Metric, 0, len(data)/blocklistLen)
	for entry := range slices.Chunk(data, blocklistLen) {
		expiry := binary.BigEndian.Uint32(entry[8:12])
		reason := uint8(expiry >> 24)
		// Bit 23 selects the unit of the remaining time, seconds if set and
		// milliseconds otherwise.
		remaining := uint64(expiry & 0x7FFFFF)
		if expiry&0x800000 != 0 {
			remaining *= 1000
		}

		tags := map[string]string{
			"local_interface":  formatID(binary.BigEndian.Uint32(entry[0:4])),
			"remote_interface": formatID(binary.BigEndian.Uint32(entry[4:8])),
			"reason":           lookup(blocklistReasons, reason),
		}
		fields := map[string]any{
			"reason_code":         uint64(reason),
			"expiry_remaining_ms": remaining,
		}
		metrics = append(metrics, p.metric("urwb_blocklist", tags, fields))
	}

	return metrics, nil
}

func checkAligned(data []byte, size int) error {
	if len(data)%size != 0 {
		return fmt.Errorf("length %d is not a multiple of the entry size %d", len(data), size)
	}
	return nil
}

func channelWidthMHz(code uint16) uint64 {
	switch code {
	case 1:
		return 20
	case 2, 3:
		return 40
	case 4:
		return 5
	case 5:
		return 10
	case 6:
		return 80
	case 7:
		return 160
	}
	return 0
}

// formatID formats mesh IDs, vehicle IDs and interface IPs in dotted-decimal
// notation
func formatID(v uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b).String()
}

func lookup(names map[uint8]string, code uint8) string {
	if name, found := names[code]; found {
		return name
	}
	return strconv.FormatUint(uint64(code), 10)
}

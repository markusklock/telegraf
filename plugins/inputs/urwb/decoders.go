package urwb

import (
	"encoding/binary"
	"fmt"
	"strings"
)

var blocklistReasons = map[uint8]string{
	0: "unspecified",
	1: "fastdrop",
	2: "poleban",
	3: "rssiban",
	4: "handoff_fail",
	5: "handoff_reject",
}

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

func decodeFHCtrlVehicle(ctx *decodeContext, data []byte) error {
	return decodeFHCtrl(ctx, data, false, "vehicle")
}

func decodeFHCtrlVehicleMulti(ctx *decodeContext, data []byte) error {
	return decodeFHCtrl(ctx, data, true, "vehicle_multi_radio")
}

func decodeFHCtrl(ctx *decodeContext, data []byte, idsAsIP bool, variant string) error {
	if len(data) < fhctrlStateLen {
		return fmt.Errorf("fhctrl header too short: have %d need %d", len(data), fhctrlStateLen)
	}
	state := data[:fhctrlStateLen]
	currSBR := binary.BigEndian.Uint32(state[0:4])
	currMBR := binary.BigEndian.Uint32(state[4:8])
	currSeq := binary.BigEndian.Uint32(state[8:12])
	hoRetries := state[20]
	hoFlags := state[21]
	hoAge := binary.BigEndian.Uint32(state[22:26])
	dopRaw := binary.BigEndian.Uint32(state[26:30])
	flags := binary.BigEndian.Uint16(state[30:32])
	inhibit := binary.BigEndian.Uint16(state[32:34])

	dopValue, dopColor := splitDOP(dopRaw)
	tags := map[string]string{
		"variant": variant,
	}
	if currSBR != 0 {
		tags["current_sbr"] = formatID(currSBR, idsAsIP)
	}
	if currMBR != 0 {
		tags["current_mbr"] = formatID(currMBR, idsAsIP)
	}

	fields := map[string]interface{}{
		"current_sequence":    currSeq,
		"handoff_retries":     uint64(hoRetries),
		"handoff_pending":     hoFlags&0x40 != 0,
		"handoff_failed":      hoFlags&0x80 != 0,
		"dop_value":           uint64(dopValue),
		"dop_color":           uint64(dopColor),
		"flags_raw":           uint64(flags),
		"flag_wireless_relay": flags&0x0001 != 0,
		"flag_can_accept":     flags&0x0002 != 0,
		"flag_is_critical":    flags&0x0004 != 0,
		"flag_freq_scan":      flags&0x0008 != 0,
		"inhibit_mask":        uint64(inhibit),
	}
	if hoAge != 0xFFFFFFFF {
		fields["handoff_age_ms"] = uint64(hoAge)
	}

	ctx.emit("urwb_fhctrl_state", fields, tags)

	entries := data[fhctrlStateLen:]
	if len(entries)%fhctrlEntryLen != 0 {
		return fmt.Errorf("fhctrl entries misaligned: %d bytes", len(entries))
	}
	if len(entries) == 0 {
		return nil
	}

	for idx := 0; idx < len(entries); idx += fhctrlEntryLen {
		entry := entries[idx : idx+fhctrlEntryLen]
		sbr := binary.BigEndian.Uint32(entry[0:4])
		mbr := binary.BigEndian.Uint32(entry[4:8])
		dop := binary.BigEndian.Uint32(entry[8:12])
		chanInfo := binary.BigEndian.Uint16(entry[12:14])
		age := binary.BigEndian.Uint16(entry[14:16])
		rssi := int(int8(entry[16]))
		eflags := entry[17]

		chanNum := uint8(chanInfo & 0x00FF)
		widthCode := uint8((chanInfo >> 12) & 0x0F)
		widthMHz := channelWidthFromCode(widthCode)
		dopVal, dopColor := splitDOP(dop)
		linkID := (eflags >> 5) & 0x07

		entryTags := map[string]string{
			"variant": variant,
			"sbr_id":  formatID(sbr, idsAsIP),
			"mbr_id":  formatID(mbr, idsAsIP),
		}
		fields := map[string]interface{}{
			"channel_number":     uint64(chanNum),
			"channel_width_code": uint64(widthCode),
			"flags_raw":          uint64(eflags),
			"dop_value":          uint64(dopVal),
			"dop_color":          uint64(dopColor),
			"age_ms":             uint64(age),
			"rssi_dbm":           int64(rssi),
			"scanning":           eflags&0x01 != 0,
			"active_link":        eflags&0x10 != 0,
			"link_id":            uint64(linkID),
		}
		if widthMHz != 0 {
			fields["channel_width_mhz"] = uint64(widthMHz)
		}
		ctx.emit("urwb_fhctrl_neighbor", fields, entryTags)
	}

	return nil
}

func decodeTitan(ctx *decodeContext, data []byte) error {
	if len(data) < titanHeaderLen {
		return fmt.Errorf("titan tlv too short: %d", len(data))
	}
	eventType := data[0] & 0x0F
	eventReason := data[1] & 0x0F
	eventDomain := (data[1] >> 4) & 0x01
	count := binary.BigEndian.Uint32(data[10:14])
	master := binary.BigEndian.Uint32(data[14:18])
	backup := binary.BigEndian.Uint32(data[18:22])

	tags := map[string]string{
		"event_type":   lookupString(titanEventTypes, eventType),
		"event_reason": lookupString(titanEventReasons, eventReason),
		"event_domain": lookupString(titanEventDomains, eventDomain),
	}
	fields := map[string]interface{}{
		"event_type_code":   uint64(eventType),
		"event_reason_code": uint64(eventReason),
		"event_domain_code": uint64(eventDomain),
		"event_count":       uint64(count),
	}
	if master != 0 {
		fields["master_id"] = meshIDString(master)
	}
	if backup != 0 {
		fields["backup_id"] = meshIDString(backup)
	}
	ctx.emit("urwb_titan_event", fields, tags)
	return nil
}

func decodeEthThroughput(ctx *decodeContext, data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("eth throughput tlv too short: %d", len(data))
	}
	numTX := int(binary.BigEndian.Uint16(data[0:2]))
	entries := data[2:]
	if len(entries)%ethEntryLen != 0 {
		return fmt.Errorf("eth entry misaligned: %d", len(entries))
	}
	total := len(entries) / ethEntryLen
	for i := 0; i < total; i++ {
		entry := entries[i*ethEntryLen : (i+1)*ethEntryLen]
		src := ipString(binary.BigEndian.Uint32(entry[0:4]))
		dst := ipString(binary.BigEndian.Uint32(entry[4:8]))
		tpt := binary.BigEndian.Uint32(entry[8:12])
		pkts := binary.BigEndian.Uint32(entry[12:16])
		direction := "rx"
		if i < numTX {
			direction = "tx"
		}
		tags := map[string]string{
			"direction":        direction,
			"src_interface_id": src,
			"dst_interface_id": dst,
		}
		fields := map[string]interface{}{
			"throughput":  uint64(tpt),
			"packets":     uint64(pkts),
			"entry_index": uint64(i),
		}
		ctx.emit("urwb_eth_flow", fields, tags)
	}
	return nil
}

func decodeMultipath(ctx *decodeContext, data []byte) error {
	offset := 0
	entryIdx := 0
	for offset+4 <= len(data) {
		flags := data[offset]
		numPeers := int(data[offset+1])
		age := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		needed := numPeers * 4
		if offset+needed > len(data) {
			return fmt.Errorf("multipath entry %d truncated", entryIdx)
		}
		peersData := data[offset : offset+needed]
		offset += needed

		peerStrings := make([]string, 0, numPeers)
		meshStrings := make([]string, 0, numPeers)
		for i := 0; i < numPeers; i++ {
			raw := binary.BigEndian.Uint32(peersData[i*4 : (i+1)*4])
			mesh := meshIDString(raw & 0x00FFFFFF)
			localIf := (raw >> 24) & 0x0F
			remoteIf := (raw >> 28) & 0x0F
			peerStrings = append(peerStrings, fmt.Sprintf("%s(l%d,r%d)", mesh, localIf, remoteIf))
			meshStrings = append(meshStrings, mesh)
		}

		pathID := (flags >> 5) & 0x07
		tags := map[string]string{
			"path_id": fmt.Sprintf("%d", pathID),
		}
		fields := map[string]interface{}{
			"flags_raw":           uint64(flags),
			"mobility_lsp":        flags&0x01 != 0,
			"destination_gateway": flags&0x04 != 0,
			"num_peers":           uint64(numPeers),
			"age_seconds":         uint64(age),
			"peers":               strings.Join(peerStrings, ","),
		}
		if len(meshStrings) > 0 {
			fields["endpoint_mesh_ids"] = strings.Join(meshStrings, ",")
		}
		ctx.emit("urwb_multipath_route", fields, tags)
		entryIdx++
	}
	if offset != len(data) {
		return fmt.Errorf("multipath trailing bytes: %d", len(data)-offset)
	}
	return nil
}

func decodeTxStatsMulti(ctx *decodeContext, data []byte) error {
	if len(data)%txStatsEntryLen != 0 {
		return fmt.Errorf("tx stats misaligned: %d", len(data))
	}
	for idx := 0; idx < len(data); idx += txStatsEntryLen {
		entry := data[idx : idx+txStatsEntryLen]
		src := ipString(binary.BigEndian.Uint32(entry[0:4]))
		dst := ipString(binary.BigEndian.Uint32(entry[4:8]))
		sent := binary.BigEndian.Uint32(entry[8:12])
		retries := binary.BigEndian.Uint32(entry[12:16])
		failed := binary.BigEndian.Uint32(entry[16:20])
		bytes := binary.BigEndian.Uint32(entry[20:24])
		age := binary.BigEndian.Uint16(entry[24:26])
		txFlags := entry[26]
		txMCS := entry[27]

		tags := map[string]string{
			"src_interface_id": src,
			"dst_interface_id": dst,
		}
		mcsType := (txFlags >> 4) & 0x03
		giCode := (txFlags >> 6) & 0x03
		fields := map[string]interface{}{
			"packets_sent":        uint64(sent),
			"packets_retried":     uint64(retries),
			"packets_failed":      uint64(failed),
			"bytes_sent":          uint64(bytes),
			"age_ms":              uint64(age),
			"tx_flags":            uint64(txFlags),
			"tx_mcs":              uint64(txMCS),
			"mcs_type":            uint64(mcsType),
			"guard_interval_code": uint64(giCode),
		}
		if bw := bandwidthHintFromFlags(txFlags); bw != 0 {
			fields["bandwidth_hint_mhz"] = uint64(bw)
		}
		if gi := guardIntervalFromCode(giCode); gi != 0 {
			fields["guard_interval_ns"] = uint64(gi)
		}
		ctx.emit("urwb_tx_stats", fields, tags)
	}
	return nil
}

func decodeRxStatsMulti(ctx *decodeContext, data []byte) error {
	if len(data)%rxStatsEntryLen != 0 {
		return fmt.Errorf("rx stats misaligned: %d", len(data))
	}
	for idx := 0; idx < len(data); idx += rxStatsEntryLen {
		entry := data[idx : idx+rxStatsEntryLen]
		src := ipString(binary.BigEndian.Uint32(entry[0:4]))
		dst := ipString(binary.BigEndian.Uint32(entry[4:8]))
		recv := binary.BigEndian.Uint32(entry[8:12])
		bytes := binary.BigEndian.Uint32(entry[12:16])
		rssi := int(int8(entry[16]))
		rxMCS := entry[17]
		rxFlags := entry[18]
		age := binary.BigEndian.Uint16(entry[20:22])

		tags := map[string]string{
			"src_interface_id": src,
			"dst_interface_id": dst,
		}
		mcsType := (rxFlags >> 4) & 0x03
		giCode := (rxFlags >> 6) & 0x03
		fields := map[string]interface{}{
			"packets_received":    uint64(recv),
			"bytes_received":      uint64(bytes),
			"rssi_dbm":            int64(rssi),
			"rx_mcs":              uint64(rxMCS),
			"rx_flags":            uint64(rxFlags),
			"mcs_type":            uint64(mcsType),
			"guard_interval_code": uint64(giCode),
			"age_ms":              uint64(age),
		}
		if bw := bandwidthHintFromFlags(rxFlags); bw != 0 {
			fields["bandwidth_hint_mhz"] = uint64(bw)
		}
		if gi := guardIntervalFromCode(giCode); gi != 0 {
			fields["guard_interval_ns"] = uint64(gi)
		}
		ctx.emit("urwb_rx_stats", fields, tags)
	}
	return nil
}

func decodeHandoffTable(ctx *decodeContext, data []byte) error {
	return decodeHandoff(ctx, data, "primary", false)
}

func decodeHandoffTableMPO(ctx *decodeContext, data []byte) error {
	return decodeHandoff(ctx, data, "secondary", true)
}

func decodeHandoff(ctx *decodeContext, data []byte, variant string, hasURWFlags bool) error {
	offset := 0
	for offset+l3HandoffBaseLen <= len(data) {
		base := data[offset : offset+l3HandoffBaseLen]
		offset += l3HandoffBaseLen
		sbr := ipString(binary.BigEndian.Uint32(base[0:4]))
		mbr := ipString(binary.BigEndian.Uint32(base[4:8]))
		master := meshIDString(binary.BigEndian.Uint32(base[8:12]))
		vehicleID := meshIDString(binary.BigEndian.Uint32(base[12:16]))
		hoSeq := binary.BigEndian.Uint32(base[16:20])
		age := binary.BigEndian.Uint32(base[20:24])
		flagsByte := byte(0)
		if hasURWFlags {
			flagsByte = base[24]
		}
		numUnits := int(base[25])
		unitsLen := numUnits * 4
		if offset+unitsLen > len(data) {
			return fmt.Errorf("handoff %s truncated units", variant)
		}
		unitsData := data[offset : offset+unitsLen]
		offset += unitsLen

		units := make([]string, 0, numUnits)
		for i := 0; i < numUnits; i++ {
			units = append(units, meshIDString(binary.BigEndian.Uint32(unitsData[i*4:(i+1)*4])))
		}

		tags := map[string]string{
			"variant": variant,
			"sbr_ip":  sbr,
			"mbr_ip":  mbr,
		}
		fields := map[string]interface{}{
			"master_mesh_id": master,
			"vehicle_id":     vehicleID,
			"handoff_seq":    uint64(hoSeq),
			"age_ms":         uint64(age),
			"num_units":      uint64(numUnits),
		}
		if len(units) > 0 {
			fields["unit_mesh_ids"] = strings.Join(units, ",")
		}
		if hasURWFlags {
			fields["urw_flags"] = uint64(flagsByte)
			fields["path_id"] = uint64(flagsByte & 0x07)
		}
		ctx.emit("urwb_handoff", fields, tags)
	}
	if offset != len(data) {
		return fmt.Errorf("handoff %s trailing bytes: %d", variant, len(data)-offset)
	}
	return nil
}

func decodeAggrTraffic(ctx *decodeContext, data []byte) error {
	if len(data) < aggrEthTrafficLen {
		return fmt.Errorf("aggr traffic tlv too short: %d", len(data))
	}
	eth := data[:aggrEthTrafficLen]
	fields := map[string]interface{}{
		"rx_kbps": uint64(binary.BigEndian.Uint32(eth[0:4])),
		"tx_kbps": uint64(binary.BigEndian.Uint32(eth[4:8])),
	}
	ctx.emit("urwb_aggr_eth", fields, map[string]string{})

	wlan := data[aggrEthTrafficLen:]
	if len(wlan)%aggrWlanTrafficLen != 0 {
		return fmt.Errorf("aggr wlan misaligned: %d", len(wlan))
	}
	for idx := 0; idx < len(wlan); idx += aggrWlanTrafficLen {
		entry := wlan[idx : idx+aggrWlanTrafficLen]
		tags := map[string]string{
			"iface_index": fmt.Sprintf("%d", idx/aggrWlanTrafficLen),
		}
		fields := map[string]interface{}{
			"rx_kbps":            uint64(binary.BigEndian.Uint32(entry[0:4])),
			"tx_kbps":            uint64(binary.BigEndian.Uint32(entry[4:8])),
			"available_capacity": uint64(binary.BigEndian.Uint32(entry[8:12])),
		}
		ctx.emit("urwb_aggr_wlan", fields, tags)
	}
	return nil
}

func decodeRadioConfig(ctx *decodeContext, data []byte) error {
	if len(data)%radioConfigLen != 0 {
		return fmt.Errorf("radio config misaligned: %d", len(data))
	}
	for idx := 0; idx < len(data); idx += radioConfigLen {
		entry := data[idx : idx+radioConfigLen]
		devInfo := entry[0]
		mode := entry[1]
		mac := macString(entry[2:8])
		status := entry[8]
		txPower := int(int8(entry[9]))
		cwidth := binary.BigEndian.Uint16(entry[10:12]) & 0x0FFF
		freq1 := binary.BigEndian.Uint32(entry[12:16]) & 0x1FFFF
		freq2 := binary.BigEndian.Uint32(entry[16:20]) & 0x1FFFF

		radioID := devInfo & 0x03
		tags := map[string]string{
			"radio_id": fmt.Sprintf("%d", radioID),
		}
		fields := map[string]interface{}{
			"mac_address":           mac,
			"mode_code":             uint64(mode & 0x07),
			"interface_enabled":     mode&0x10 != 0,
			"he_enabled":            mode&0x20 != 0,
			"tdma_mode":             status&0x20 != 0,
			"scanning":              status&0x40 != 0,
			"tx_disabled":           status&0x80 != 0,
			"tx_power_dbm":          int64(txPower),
			"channel_width_mhz":     uint64(cwidth),
			"primary_frequency_mhz": uint64(freq1),
		}
		if freq2 != 0 {
			fields["secondary_frequency_mhz"] = uint64(freq2)
		}
		ctx.emit("urwb_radio_config", fields, tags)
	}
	return nil
}

func decodeMPOExt(ctx *decodeContext, data []byte) error {
	if len(data)%mpoExtEntryLen != 0 {
		return fmt.Errorf("mpo ext misaligned: %d", len(data))
	}
	for idx := 0; idx < len(data); idx += mpoExtEntryLen {
		entry := data[idx : idx+mpoExtEntryLen]
		mac := macString(entry[0:6])
		fields := map[string]interface{}{
			"tx_primary":          uint64(binary.BigEndian.Uint32(entry[6:10])),
			"tx_secondary":        uint64(binary.BigEndian.Uint32(entry[10:14])),
			"rx_primary_accept":   uint64(binary.BigEndian.Uint32(entry[14:18])),
			"rx_primary_drop":     uint64(binary.BigEndian.Uint32(entry[18:22])),
			"rx_secondary_accept": uint64(binary.BigEndian.Uint32(entry[22:26])),
			"rx_secondary_drop":   uint64(binary.BigEndian.Uint32(entry[26:30])),
			"lost_both":           uint64(binary.BigEndian.Uint32(entry[30:34])),
			"lost_primary_only":   uint64(binary.BigEndian.Uint32(entry[34:38])),
		}
		tags := map[string]string{
			"client_mac": mac,
		}
		ctx.emit("urwb_mpo_ext", fields, tags)
	}
	return nil
}

func decodeBlocklist(ctx *decodeContext, data []byte) error {
	if len(data)%blocklistEntryLen != 0 {
		return fmt.Errorf("blocklist misaligned: %d", len(data))
	}
	for idx := 0; idx < len(data); idx += blocklistEntryLen {
		entry := data[idx : idx+blocklistEntryLen]
		local := ipString(binary.BigEndian.Uint32(entry[0:4]))
		remote := ipString(binary.BigEndian.Uint32(entry[4:8]))
		expiry := binary.BigEndian.Uint32(entry[8:12])
		reason := uint8(expiry >> 24)
		scale := (expiry >> 23) & 0x1
		remaining := expiry & 0x7FFFFF
		remainingMs := remaining
		if scale == 1 {
			remainingMs *= 1000
		}
		tags := map[string]string{
			"local_interface":  local,
			"remote_interface": remote,
			"reason":           lookupString(blocklistReasons, reason),
		}
		fields := map[string]interface{}{
			"reason_code":          uint64(reason),
			"expiry_scale_seconds": scale == 1,
			"expiry_remaining_ms":  uint64(remainingMs),
		}
		ctx.emit("urwb_blocklist", fields, tags)
	}
	return nil
}

func lookupString(m map[uint8]string, k uint8) string {
	if v, ok := m[k]; ok {
		return v
	}
	return fmt.Sprintf("%d", k)
}

func splitDOP(v uint32) (uint16, uint16) {
	return uint16(v & 0xFFFF), uint16((v >> 16) & 0xFFFF)
}

func channelWidthFromCode(code uint8) int {
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
	default:
		return 0
	}
}

func bandwidthHintFromFlags(flags byte) int {
	switch {
	case flags&0x08 != 0:
		return 160
	case flags&0x04 != 0:
		return 80
	case flags&0x01 != 0:
		return 40
	default:
		return 20
	}
}

func guardIntervalFromCode(code uint8) int {
	switch code {
	case 0:
		return 800
	case 1:
		return 400
	case 2:
		return 1600
	case 3:
		return 3200
	default:
		return 0
	}
}

func formatID(v uint32, asIP bool) string {
	if asIP {
		return ipString(v)
	}
	return meshIDString(v)
}

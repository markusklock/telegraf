# Cisco Ultra-Reliable Wireless Backhaul (URWB) Input Plugin

This service plugin receives telemetry sent by devices running Cisco
[Ultra-Reliable Wireless Backhaul (URWB)][urwb], such as Catalyst IW9165 and
IW9167 access points. Packets are decoded according to the
[URWB Telemetry Protocol specification][spec] (revision 2.0.19) and provide
information about link quality, handoffs, routing, radio configuration and
traffic of the wireless network.

⭐ Telegraf v1.41.0
🏷️ network, iot
💻 all

[urwb]: https://www.cisco.com/site/us/en/products/networking/industrial-wireless/ultra-reliable-wireless-backhaul/index.html
[spec]: https://www.cisco.com/c/en/us/td/docs/wireless/outdoor_industrial/iw9167/reference/URWB_Telemetry_Protocol_2-0-19.html

## Service Input <!-- @/docs/includes/service_input.md -->

This plugin is a service input. Normal plugins gather metrics determined by the
interval setting. Service plugins start a service to listen and wait for
metrics or events to occur. Service plugins have two key differences from
normal plugins:

1. The global or plugin specific `interval` setting may not apply
2. The CLI options of `--test`, `--test-wait`, and `--once` may not produce
   output for this plugin

## Global configuration options <!-- @/docs/includes/plugin_config.md -->

Plugins support additional global and plugin configuration settings for tasks
such as modifying metrics, tags, and fields, creating aliases, and configuring
plugin ordering. See [CONFIGURATION.md][CONFIGURATION.md] for more details.

[CONFIGURATION.md]: ../../../docs/CONFIGURATION.md#plugins

## Configuration

```toml @sample.conf
# Cisco Ultra-Reliable Wireless Backhaul (URWB) telemetry listener
[[inputs.cisco_urwb]]
  ## Address and port to listen on for URWB telemetry packets.
  ##   example: service_address = "udp://:30000"
  ##            service_address = "udp4://:30000"
  ##            service_address = "udp6://:30000"
  service_address = "udp://:30000"

  ## Size of the operating system's receive buffer. Increase this value if
  ## packets get dropped under high load. Uses the system's default if unset.
  ##   example: read_buffer_size = "4MiB"
  # read_buffer_size = ""

  ## Source IP addresses or networks in CIDR notation allowed to send
  ## telemetry. Packets from other sources are dropped. If empty, packets from
  ## all sources are accepted.
  ##   example: allowed_sources = ["10.0.0.0/8", "192.168.1.10"]
  # allowed_sources = []

  ## Log the content of received packets as hex dump for troubleshooting.
  # log_level = "trace"
```

The devices must be configured to send telemetry to the address and port the
plugin listens on. URWB devices send telemetry to UDP port 30000 by default.

## Metrics

Each packet contains a header followed by a number of Type-Length-Value (TLV)
records. The plugin emits one `urwb_packet` metric per packet and additional
metrics for each supported TLV. Unsupported TLVs, such as `GNSS_NMEA (0x027)`,
are skipped.

URWB identifiers such as mesh IDs, vehicle IDs and interface IDs are formatted
in dotted-decimal notation (e.g. `5.55.54.17`). Depending on the TLV, units are
identified either by their mesh ID or by the ID of a specific radio interface.

The header timestamp of a packet is based on the internal clock of the device
and not on wall-clock time. Therefore, all metrics use the time the packet was
received as timestamp.

All metrics have the following tags:

- `source`: IP address of the device sending the packet
- `mesh_id`: mesh ID of the device, omitted if not set
- `vehicle_id`: vehicle ID of the device, omitted if not set
- `meshend_id`: ID of the mesh-end currently used by the device, omitted if
  not set

The following metrics are emitted in addition:

- `urwb_packet`: one metric per packet
  - fields:
    - `seq` (unsigned integer): sequence number of the packet
    - `flags` (unsigned integer): message flags of the packet header
    - `tlv_count` (unsigned integer): number of TLVs in the packet including
      unsupported TLVs

- `urwb_fhctrl_state`: handoff state of a mobile unit decoded from the
  `FHCTRL_VEHICLE (0x001)` and `FHCTRL_VEHICLE_MULTI_RADIO (0x01D)` TLVs
  - tags:
    - `variant`: `vehicle` for TLV 0x001 or `vehicle_multi_radio` for TLV 0x01D
    - `current_sbr`: infrastructure unit of the current handoff, omitted if
      not set
    - `current_mbr`: mobile unit of the current handoff, omitted if not set
  - fields:
    - `current_sequence` (unsigned integer): sequence number of the current
      handoff
    - `handoff_retries` (unsigned integer): number of handoff retries
    - `handoff_pending` (boolean): handoff in progress
    - `handoff_failed` (boolean): last handoff failed
    - `handoff_age_ms` (unsigned integer, milliseconds): time since the last
      successful handoff, omitted if not available
    - `dop_value` (unsigned integer): DoP value of the unit
    - `dop_color` (unsigned integer): DoP color information of the unit
    - `flags_raw` (unsigned integer): raw state flags
    - `flag_wireless_relay` (boolean): wireless relay flag
    - `flag_can_accept` (boolean): CanAccept flag
    - `flag_is_critical` (boolean): IsCritical flag
    - `flag_freq_scan` (boolean): frequency scan in progress
    - `inhibit_mask` (unsigned integer): handoff inhibition mask

- `urwb_fhctrl_neighbor`: neighbor entry of the `FHCTRL_VEHICLE (0x001)` and
  `FHCTRL_VEHICLE_MULTI_RADIO (0x01D)` TLVs
  - tags:
    - `variant`: `vehicle` for TLV 0x001 or `vehicle_multi_radio` for TLV 0x01D
    - `sbr`: infrastructure unit
    - `mbr`: mobile unit
  - fields:
    - `channel_number` (unsigned integer): channel number
    - `channel_width_code` (unsigned integer): raw channel width code
    - `channel_width_mhz` (unsigned integer, MHz): channel width, omitted for
      invalid codes
    - `dop_value` (unsigned integer): DoP value advertised by the remote unit
    - `dop_color` (unsigned integer): DoP color advertised by the remote unit
    - `age_ms` (unsigned integer, milliseconds): time since the last update
    - `rssi_dbm` (integer, dBm): received signal strength
    - `flags_raw` (unsigned integer): raw entry flags
    - `scanning` (boolean): entry was added during a scan
    - `active_link` (boolean): link is active
    - `link_id` (unsigned integer): ID of the link

- `urwb_titan_event`: fast-failover event from the `TITAN (0x00A)` TLV
  - tags:
    - `event_type`: `topology_change`, `mobile_failover`, `mesh_end_failover`
      or `global_gateway_failover`
    - `event_reason`: `unspecified`, `link_failure`, `node_failure` or
      `recovery`
    - `event_domain`: `local` or `remote`
  - fields:
    - `event_type_code` (unsigned integer): raw event type
    - `event_reason_code` (unsigned integer): raw event reason
    - `event_domain_code` (unsigned integer): raw event domain
    - `event_count` (unsigned integer): event counter
    - `master_id` (string): mesh ID of the primary unit after the event,
      omitted if not available
    - `backup_id` (string): mesh ID of the previous primary unit, omitted if
      not available

- `urwb_eth_flow`: Ethernet flow from the `ETH_TPT (0x00D)` TLV
  - tags:
    - `direction`: `tx` or `rx`
    - `src_address`: IP address of the source station
    - `dst_address`: IP address of the destination station
  - fields:
    - `throughput` (unsigned integer): throughput of the flow
    - `packets` (unsigned integer): number of packets of the flow

- `urwb_multipath_route`: redundant route from the `MULTIPATH (0x01B)` TLV
  - tags:
    - `destination`: mesh ID of the end of the route that is not the
      reporting unit
    - `path_id`: Multipath Operation (MPO) path ID, omitted for empty routes
  - fields:
    - `flags_raw` (unsigned integer): raw route flags
    - `mobility_lsp` (boolean): route is a mobility LSP
    - `destination_gateway` (boolean): destination is the global gateway
    - `num_peers` (unsigned integer): number of peers in the route; a value of
      one denotes an empty route, notifying that all routes to the
      destination were removed
    - `peers` (string): comma-separated list of mesh IDs in the route
    - `peer_interfaces` (string): comma-separated list of local and remote
      interface IDs as `local:remote` for each peer
    - `age_seconds` (unsigned integer, seconds): time since the route was
      refreshed, omitted for empty routes

  > [!NOTE]
  > The protocol only includes the lowest three octets of the mesh IDs in
  > this TLV, so the first octet is always zero (e.g. `0.55.54.17`).

- `urwb_tx_stats`: wireless transmit statistics from the
  `TX_STATS_MULTI_RADIO (0x01E)` TLV
  - tags:
    - `src_interface`: interface ID of the source station
    - `dst_interface`: interface ID of the destination station
  - fields:
    - `packets_sent` (unsigned integer): number of transmitted packets
    - `packets_retried` (unsigned integer): number of transmission retries
    - `packets_failed` (unsigned integer): number of lost packets
    - `bytes_sent` (unsigned integer, bytes): number of transmitted bytes
    - `age_ms` (unsigned integer, milliseconds): time since the last feedback
    - `mcs` (unsigned integer): modulation and coding scheme
    - `flags_raw` (unsigned integer): raw transmit flags
    - `bandwidth_hint_mhz` (unsigned integer, MHz): channel width of 20, 40,
      80 or 160 MHz, with 5 and 10 MHz reported as 20 MHz
    - `mcs_type` (unsigned integer): `0` for no HT, `1` for HT, `2` for VHT
      and `3` for HE
    - `guard_interval_code` (unsigned integer): raw guard interval code
    - `guard_interval_ns` (unsigned integer, nanoseconds): guard interval

- `urwb_rx_stats`: wireless receive statistics from the
  `RX_STATS_MULTI_RADIO (0x01F)` TLV
  - tags:
    - `src_interface`: interface ID of the source station
    - `dst_interface`: interface ID of the destination station
  - fields:
    - `packets_received` (unsigned integer): number of received packets
    - `bytes_received` (unsigned integer, bytes): number of received bytes
    - `rssi_dbm` (integer, dBm): received signal strength
    - `mcs` (unsigned integer): modulation and coding scheme
    - `age_ms` (unsigned integer, milliseconds): time since the last update
    - `flags_raw` (unsigned integer): raw receive flags
    - `bandwidth_hint_mhz` (unsigned integer, MHz): see `urwb_tx_stats`
    - `mcs_type` (unsigned integer): see `urwb_tx_stats`
    - `guard_interval_code` (unsigned integer): raw guard interval code
    - `guard_interval_ns` (unsigned integer, nanoseconds): guard interval

- `urwb_handoff`: established connection between mobile and infrastructure
  units from the `HANDOFF_TBL_MULTI_RADIO (0x021)` and
  `HANDOFF_TBL_MULTI_RADIO_MPO (0x025)` TLVs
  - tags:
    - `variant`: `primary` for TLV 0x021 or `secondary` for TLV 0x025
    - `path_id`: MPO path ID, always `0` for the primary path
    - `sbr`: interface ID of the infrastructure unit
    - `mbr`: interface ID of the mobile unit
  - fields:
    - `master_id` (string): mesh ID of the mobile master unit
    - `remote_vehicle_id` (string): vehicle ID of the remote vehicle
    - `handoff_seq` (unsigned integer): handoff sequence number
    - `age_ms` (unsigned integer, milliseconds): time since the last handoff
      update
    - `num_units` (unsigned integer): number of on-board units
    - `unit_ids` (string): comma-separated list of on-board unit mesh IDs,
      omitted if there are no units

- `urwb_aggr_eth`: aggregated Ethernet traffic from the
  `AGGR_TRAFFIC_MULTI_RADIO (0x022)` TLV
  - fields:
    - `rx_kbps` (unsigned integer, kbps): received traffic
    - `tx_kbps` (unsigned integer, kbps): transmitted traffic

- `urwb_aggr_wlan`: aggregated wireless traffic per interface from the
  `AGGR_TRAFFIC_MULTI_RADIO (0x022)` TLV
  - tags:
    - `iface_index`: index of the wireless interface
  - fields:
    - `rx_kbps` (unsigned integer, kbps): received traffic
    - `tx_kbps` (unsigned integer, kbps): transmitted traffic
    - `available_capacity` (unsigned integer): available link capacity

- `urwb_radio_config`: radio configuration from the
  `RADIO_CFG_MULTI_RADIO (0x023)` TLV
  - tags:
    - `radio_id`: ID of the radio interface
    - `mode`: operating mode, `unused`, `fluidity`, `fixed_infrastructure`,
      `fluidmax` or `bridge`
  - fields:
    - `mac_address` (string): MAC address of the radio interface
    - `mode_code` (unsigned integer): raw operating mode
    - `interface_enabled` (boolean): interface is enabled
    - `he_enabled` (boolean): 802.11ax (HE) is enabled
    - `tdma_mode` (boolean): TDMA is used instead of CSMA
    - `scanning` (boolean): frequency scan in progress
    - `tx_disabled` (boolean): transmission is disabled
    - `tx_power_dbm` (integer, dBm): transmit power
    - `channel_width_mhz` (unsigned integer, MHz): channel width
    - `primary_frequency_mhz` (unsigned integer, MHz): primary frequency
    - `secondary_frequency_mhz` (unsigned integer, MHz): secondary frequency,
      omitted if not set

- `urwb_mpo_ext`: Multipath Operation (MPO) statistics per client from the
  `MPO EXT (0x024)` TLV
  - tags:
    - `client_mac`: MAC address of the client
  - fields:
    - `tx_primary` (unsigned integer): packets transmitted on the primary path
    - `tx_secondary` (unsigned integer): packets transmitted on the secondary
      path
    - `rx_primary_accept` (unsigned integer): packets accepted on the primary
      path
    - `rx_primary_drop` (unsigned integer): packets dropped on the primary
      path
    - `rx_secondary_accept` (unsigned integer): packets accepted on the
      secondary path
    - `rx_secondary_drop` (unsigned integer): packets dropped on the secondary
      path
    - `lost_both` (unsigned integer): packets lost on both paths
    - `lost_primary_only` (unsigned integer): packets lost on the primary path
      only

- `urwb_blocklist`: blocked handoff link from the
  `BLOCKLIST MULTI-RADIO (0x026)` TLV
  - tags:
    - `local_interface`: local interface ID, `0.0.0.0` for all interfaces
    - `remote_interface`: remote interface ID, `0.0.0.0` for all interfaces
    - `reason`: `unspecified`, `fastdrop`, `poleban`, `rssiban`,
      `handoff_fail` or `handoff_reject`
  - fields:
    - `reason_code` (unsigned integer): raw reason code
    - `expiry_remaining_ms` (unsigned integer, milliseconds): time until the
      entry expires

## Troubleshooting

### Packets are dropped

Increase `read_buffer_size` if packets get lost under high load. On Linux, the
buffer size is limited by the `net.core.rmem_max` kernel setting, so you might
need to increase this limit as well.

If you set `allowed_sources`, make sure it contains the addresses of all
devices. Run Telegraf with `--debug` to log packets from disallowed sources.

### Packets cannot be decoded

Set `log_level = "trace"` in the plugin configuration to log the content of
all received packets as hex dump. Please include those dumps when reporting
decoding issues.

## Example Output

```text
urwb_packet,host=telegraf-host,mesh_id=5.55.54.17,meshend_id=5.55.255.1,source=192.168.10.17,vehicle_id=5.55.54.18 seq=42i,flags=0i,tlv_count=1i 1792054114151174708
urwb_fhctrl_state,current_mbr=5.55.54.17,current_sbr=5.1.2.3,host=telegraf-host,mesh_id=5.55.54.17,meshend_id=5.55.255.1,source=192.168.10.17,variant=vehicle,vehicle_id=5.55.54.18 handoff_pending=true,dop_value=20i,dop_color=3i,flag_wireless_relay=true,inhibit_mask=0i,handoff_age_ms=1234i,current_sequence=55i,handoff_retries=2i,handoff_failed=false,flags_raw=3i,flag_can_accept=true,flag_is_critical=false,flag_freq_scan=false 1792054114151174708
urwb_fhctrl_neighbor,host=telegraf-host,mbr=5.55.54.17,mesh_id=5.55.54.17,meshend_id=5.55.255.1,sbr=5.1.2.3,source=192.168.10.17,variant=vehicle,vehicle_id=5.55.54.18 flags_raw=48i,dop_value=16i,dop_color=1i,scanning=false,active_link=true,link_id=1i,channel_width_mhz=80i,channel_number=36i,channel_width_code=6i,age_ms=100i,rssi_dbm=-60i 1792054114151174708
urwb_fhctrl_neighbor,host=telegraf-host,mbr=5.55.54.17,mesh_id=5.55.54.17,meshend_id=5.55.255.1,sbr=5.1.2.4,source=192.168.10.17,variant=vehicle,vehicle_id=5.55.54.18 rssi_dbm=-75i,flags_raw=1i,link_id=0i,scanning=true,active_link=false,channel_width_mhz=20i,channel_number=44i,channel_width_code=1i,dop_value=24i,dop_color=2i,age_ms=500i 1792054114151174708
urwb_packet,host=telegraf-host,mesh_id=5.55.54.17,meshend_id=5.55.255.1,source=192.168.10.17,vehicle_id=5.55.54.18 seq=47i,flags=0i,tlv_count=1i 1792054114151319881
urwb_radio_config,host=telegraf-host,mesh_id=5.55.54.17,meshend_id=5.55.255.1,mode=fluidity,radio_id=0,source=192.168.10.17,vehicle_id=5.55.54.18 mac_address="00:1d:a2:11:22:33",mode_code=1i,he_enabled=true,tdma_mode=true,scanning=false,tx_disabled=false,channel_width_mhz=80i,interface_enabled=true,tx_power_dbm=18i,primary_frequency_mhz=5180i 1792054114151319881
urwb_radio_config,host=telegraf-host,mesh_id=5.55.54.17,meshend_id=5.55.255.1,mode=fixed_infrastructure,radio_id=1,source=192.168.10.17,vehicle_id=5.55.54.18 he_enabled=false,tdma_mode=false,tx_disabled=true,tx_power_dbm=-5i,channel_width_mhz=40i,primary_frequency_mhz=2412i,interface_enabled=true,scanning=true,secondary_frequency_mhz=2437i,mac_address="00:1d:a2:44:55:66",mode_code=2i 1792054114151319881
```

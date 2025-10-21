# URWB Input Plugin

The URWB (Ultra-Reliable Wireless Backhaul) input plugin receives Cisco URWB
telemetry over UDP and decodes the TLV payloads defined in the Cisco URWB
Telemetry Protocol v2.0.19. The plugin exposes key link quality, radio
configuration, handoff, and traffic statistics emitted by URWB enabled access points.

## Service Input <!-- @/docs/includes/service_input.md -->

This plugin is a service input. Normal plugins gather metrics determined by the
interval setting. Service plugins start a service to listen and wait for
metrics or events to occur. Service plugins have two key differences from
normal plugins:

1. The global or plugin specific `interval` setting may not apply
2. The CLI options of `--test`, `--test-wait`, and `--once` may not produce
   output for this plugin

## Protocol Specification

For further details see the
[Cisco URWB Telemetry Protocol Specification](https://www.cisco.com/c/en/us/td/docs/wireless/outdoor_industrial/iw9167/reference/URWB_Telemetry_Protocol_2-0-19.html).

## Global configuration options <!-- @/docs/includes/plugin_config.md -->

In addition to the plugin-specific configuration settings, plugins support
additional global and plugin configuration settings. These settings are used to
modify metrics, tags, and field or create aliases and configure ordering, etc.
See the [CONFIGURATION.md][CONFIGURATION.md] for more details.

[CONFIGURATION.md]: ../../../docs/CONFIGURATION.md#plugins

## Configuration

```toml @sample.conf
[[inputs.urwb]]
## Address to listen for URWB UDP packets
## Examples: "udp://:30000", "udp4://0.0.0.0:30000", "udp6://[::]:30000"
service_address = "udp://:30000"

## Socket read buffer (OS-level). Increase to reduce packet loss.
read_buffer_size = 4194304

## Maximum UDP datagram size to accept (bytes)
max_packet_size = 65535

## Number of decoder workers (0/1 = decode inline in the read loop)
workers = 0

## Drop packets with invalid magic or undersized header
drop_invalid = true

## Optionally restrict to allowed source IP subnets (comma-separated CIDRs)
## allowed_sources = ["10.0.0.0/8", "192.168.0.0/16"]
```

## Metrics

All measurements inherit the base tags extracted from the URWB header:

- `host`: Hostname where Telegraf is running
- `src_ip`: Source IP address of the telemetry packet (actual network IP of the device)
- `mesh_id`: Mesh ID of the emitting unit (URWB dotted identifier, when present)
- `vehicle_id`: Vehicle ID of the emitting unit (URWB dotted identifier, when present)
- `meshend_id`: Mesh-end ID of the emitting unit (URWB dotted identifier, when present)

### URWB Addressing Model

URWB uses a hierarchical addressing scheme where identifiers are formatted as dotted-decimal (IP-like) but represent different layers:

- **Mesh ID** (e.g., `5.55.54.176`): Identifies a node in the mesh
- **Interface ID** (e.g., `4.55.54.176`, `3.55.54.176`): Identifies a specific radio interface on a node
- **Network IP** (e.g., `172.22.23.6`): Actual IP address used for telemetry transport

A single node can have multiple Interface IDs (one per radio).

The following measurements are emitted depending on the TLVs present in a
packet. Boolean fields are reported as Telegraf booleans, counters are unsigned
integers unless otherwise noted.

> [!NOTE]
> URWB headers carry device uptime rather than wall-clock time. The plugin
> therefore timestamps metrics with the packet receive time.

| Measurement              | Description                              | Tags (in addition to base)                   | Key Fields (selection)                                        |
|-------------------------|------------------------------------------|----------------------------------------------|---------------------------------------------------------------|
| `urwb_packet`           | Per-packet summary                       | —                                            | `seq`, `flags`, `tlv_count`                                   |
| `urwb_fhctrl_state`     | FH control state (vehicle or multi-radio)| `variant` (`vehicle`/`vehicle_multi_radio`),<br>`current_sbr`, `current_mbr` (URWB dotted identifiers) | `current_sequence`, `handoff_retries`, `handoff_failed`, `dop_value`, `inhibit_mask`, `handoff_age_ms` |
| `urwb_fhctrl_neighbor`  | FH control neighbour entry               | `variant`, `sbr_id`, `mbr_id` (URWB dotted identifiers) | `channel_number`, `channel_width_mhz`, `rssi_dbm`, `active_link`, `link_id` |
| `urwb_titan_event`      | Titan fast-failover event                | `event_type`, `event_reason`, `event_domain` | `event_count`, `event_type_code`, `master_id`, `backup_id`     |
| `urwb_eth_flow`         | Ethernet throughput per link             | `direction` (`tx`/`rx`), `src_interface_id`, `dst_interface_id`  | `throughput`, `packets`, `entry_index`                        |
| `urwb_multipath_route`  | Multipath routing entry                  | `path_id`                                    | `num_peers`, `age_seconds`, `peers`, `mobility_lsp`            |
| `urwb_tx_stats`         | Wireless transmit statistics             | `src_interface_id`, `dst_interface_id`       | `packets_sent`, `packets_retried`, `packets_failed`, `bandwidth_hint_mhz`, `guard_interval_ns` |
| `urwb_rx_stats`         | Wireless receive statistics              | `src_interface_id`, `dst_interface_id`       | `packets_received`, `bytes_received`, `rssi_dbm`, `bandwidth_hint_mhz`, `guard_interval_ns` |
| `urwb_handoff`          | L3 handoff entry (primary/secondary)     | `variant` (`primary`/`secondary`), `sbr_ip`, `mbr_ip` | `handoff_seq`, `age_ms`, `path_id` (secondary only), `num_units`, `unit_mesh_ids` |
| `urwb_aggr_eth`         | Aggregated Ethernet throughput           | —                                            | `rx_kbps`, `tx_kbps`                                          |
| `urwb_aggr_wlan`        | Aggregated WLAN throughput per radio     | `iface_index`                                | `rx_kbps`, `tx_kbps`, `available_capacity`                     |
| `urwb_radio_config`     | Radio configuration snapshot             | `radio_id`                                   | `mac_address`, `mode_code`, `interface_enabled`, `tx_power_dbm`, `channel_width_mhz`, `primary_frequency_mhz`, `secondary_frequency_mhz` |
| `urwb_mpo_ext`          | Multi-path optimisation statistics       | `client_mac`                                 | `tx_primary`, `tx_secondary`, `rx_primary_accept`, `rx_secondary_accept`, `lost_both`, `lost_primary_only` |
| `urwb_blocklist`        | Current handoff blocklist                | `local_interface`, `remote_interface`, `reason` | `reason_code`, `expiry_scale_seconds`, `expiry_remaining_ms`   |

Additional TLV types will emit new measurements following the same naming
convention.

## Example Output

```text
urwb_packet,host=telegraf,mesh_id=170.187.204.221,meshend_id=5.6.7.8,src_ip=203.0.113.1,vehicle_id=1.2.3.4 tlv_count=1i,seq=10i,flags=0i 1700000000123000000
urwb_fhctrl_state,current_mbr=0.0.0.34,current_sbr=0.0.0.17,host=telegraf,mesh_id=170.187.204.221,src_ip=203.0.113.1,variant=vehicle vehicle_id=1.2.3.4 current_sequence=55i,handoff_retries=4i,handoff_failed=true,dop_value=2i,inhibit_mask=255i 1700000000123000000
urwb_fhctrl_neighbor,host=telegraf,mbr_id=0.0.32.0,mesh_id=170.187.204.221,src_ip=203.0.113.1,sbr_id=0.0.16.0,variant=vehicle vehicle_id=1.2.3.4 channel_number=36i,rssi_dbm=-42i,active_link=true 1700000000123000000
```

## Troubleshooting

### Packet Loss

If you're experiencing packet loss, try increasing the `read_buffer_size`:

```toml
read_buffer_size = 8388608  # 8 MiB
```

### Performance

For high-volume telemetry, enable worker-based decoding:

```toml
workers = 4  # Use 4 decoder workers
```

### Security

Restrict telemetry sources using the `allowed_sources` option:

```toml
allowed_sources = ["10.0.0.0/8", "192.168.1.0/24"]
```

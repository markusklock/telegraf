//go:build !custom || inputs || inputs.cisco_urwb

package all

import _ "github.com/influxdata/telegraf/plugins/inputs/cisco_urwb" // register plugin

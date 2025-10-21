//go:build !custom || inputs || inputs.urwb

package all

import _ "github.com/influxdata/telegraf/plugins/inputs/urwb" // register plugin

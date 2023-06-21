package standard

import (
	// standard Caddy modules
	_ "github.com/sunbird1015/caddy/v2/caddyconfig/caddyfile"
	_ "github.com/sunbird1015/caddy/v2/modules/caddyevents"
	_ "github.com/sunbird1015/caddy/v2/modules/caddyevents/eventsconfig"
	_ "github.com/sunbird1015/caddy/v2/modules/caddyhttp/standard"
	_ "github.com/sunbird1015/caddy/v2/modules/caddytls"
	_ "github.com/sunbird1015/caddy/v2/modules/caddytls/distributedstek"
	_ "github.com/sunbird1015/caddy/v2/modules/caddytls/standardstek"
	_ "github.com/sunbird1015/caddy/v2/modules/filestorage"
	_ "github.com/sunbird1015/caddy/v2/modules/logging"
	_ "github.com/sunbird1015/caddy/v2/modules/metrics"
)

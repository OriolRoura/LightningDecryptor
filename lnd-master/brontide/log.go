package brontide

import (
	"github.com/btcsuite/btclog/v2"
	"github.com/lightningnetwork/lnd/build"
)

// brontideLog is a logger that is initialized with the btclog.Disabled logger.
var brontideLog btclog.Logger

// The default amount of logging is none.
func init() {
	UseLogger(build.NewSubLogger("BRNT", nil))
}

// DisableLog disables all logging output.
func DisableLog() {
	UseLogger(btclog.Disabled)
}

// UseLogger uses a specified Logger to output package logging info.
func UseLogger(logger btclog.Logger) {
	brontideLog = logger
}

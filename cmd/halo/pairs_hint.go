package main

import (
	"errors"
	"fmt"

	"github.com/dshakes/halos/internal/shadow"
)

// plaintextPairsHint names the CLI's migration switch for an unsealed row in
// a sealed pair store (the MCP tool and halo-shadow name their own).
func plaintextPairsHint(err error) error {
	if errors.Is(err, shadow.ErrPlaintextRow) {
		return fmt.Errorf("%w: pass --allow-plaintext-pairs to read rows written before pair keys were configured (migration; otherwise the row may be injected)", err)
	}
	return err
}

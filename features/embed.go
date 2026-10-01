// Package features embeds the checked-in Dev Container Feature and Coder
// module so internal/delivery exporters and the repo share one source of truth.
package features

import "embed"

//go:embed halos/devcontainer-feature.json halos/install.sh halos/init-firewall.sh coder/main.tf
var FS embed.FS

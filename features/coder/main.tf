terraform {
  required_providers {
    coder = {
      source  = "coder/coder"
      version = ">= 2.0.0" # coder_workspace_owner (owner email as the default subject)
    }
  }
}

variable "agent_id" {
  type        = string
  description = "The coder_agent id to attach the script to."
}

variable "registry" {
  type        = string
  description = "OCI repository holding Halos releases."
  validation {
    condition     = can(regex("^[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?(/[a-zA-Z0-9][a-zA-Z0-9._-]*)+$", var.registry))
    error_message = "registry must be host[:port]/path with only [A-Za-z0-9._-] characters."
  }
}

variable "org" {
  type        = string
  description = "Org name; must equal the org in the signed release."
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9._-]{0,62}$", var.org))
    error_message = "org must match ^[a-z0-9][a-z0-9._-]{0,62}$."
  }
}

variable "ring" {
  type        = string
  default     = "ga"
  description = "Ring to follow."
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9._-]{0,62}$", var.ring))
    error_message = "ring must match ^[a-z0-9][a-z0-9._-]{0,62}$."
  }
}

variable "pubkey_pem" {
  type        = string
  description = "ed25519 release public key (PKIX PEM contents). Embedded inline; never downloaded."
  validation {
    condition     = can(regex("^-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=]+\n)+-----END PUBLIC KEY-----\n?$", var.pubkey_pem))
    error_message = "pubkey_pem must be a single PUBLIC KEY PEM block."
  }
}

variable "halod_url" {
  type        = string
  description = "halod download URL (https); {os} and {arch} are substituted. A raw binary, or a release archive when the path ends in .tar.gz (the sha256 then pins the archive, as in the release's checksums.txt)."
  validation {
    condition     = can(regex("^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%+@,=&?{}-]*)*$", var.halod_url))
    error_message = "halod_url must be a plain https URL."
  }
}

variable "halod_sha256_amd64" {
  type        = string
  description = "sha256 (hex) of the linux/amd64 halod binary, or of the archive when halod_url ends in .tar.gz."
  validation {
    condition     = can(regex("^[0-9a-fA-F]{64}$", var.halod_sha256_amd64))
    error_message = "halod_sha256_amd64 must be 64 hex characters."
  }
}

variable "halod_sha256_arm64" {
  type        = string
  description = "sha256 (hex) of the linux/arm64 halod binary, or of the archive when halod_url ends in .tar.gz."
  validation {
    condition     = can(regex("^[0-9a-fA-F]{64}$", var.halod_sha256_arm64))
    error_message = "halod_sha256_arm64 must be 64 hex characters."
  }
}

variable "subject" {
  type        = string
  default     = ""
  description = "User id for client-axis experiments (halod.yaml subject). Empty: the workspace owner's email."
  validation {
    condition     = can(regex("^[A-Za-z0-9._@+-]{0,256}$", var.subject))
    error_message = "subject must be at most 256 characters from [A-Za-z0-9._@+-] (no quotes, spaces or newlines)."
  }
}

data "coder_workspace_owner" "me" {}

locals {
  subject = var.subject != "" ? var.subject : data.coder_workspace_owner.me.email
}

# All interpolated values are regex-validated above (no quotes, $, backticks or
# newlines except the base64 PEM body), and the script embeds them only in
# single-quoted shell words / a quoted heredoc.
resource "coder_script" "halos" {
  agent_id           = var.agent_id
  display_name       = "Halos"
  icon               = "/icon/code.svg"
  run_on_start       = true
  start_blocks_login = true
  lifecycle {
    precondition {
      condition     = can(regex("^[A-Za-z0-9._@+-]{0,256}$", local.subject))
      error_message = "the workspace owner's email is not usable as a subject; set the subject variable."
    }
  }
  script = <<-EOT
    #!/usr/bin/env bash
    set -euo pipefail
    case "$(uname -m)" in
      x86_64) arch=amd64; want='${var.halod_sha256_amd64}' ;;
      *) arch=arm64; want='${var.halod_sha256_arm64}' ;;
    esac
    url='${var.halod_url}'; url="$${url//\{os\}/linux}"; url="$${url//\{arch\}/$arch}"
    tmp="$(mktemp)"; d="$(mktemp -d)"; trap 'rm -rf "$tmp" "$d"' EXIT
    curl -fsSL "$url" -o "$tmp"
    echo "$want  $tmp" | sha256sum -c - >/dev/null || { echo "halod sha256 mismatch" >&2; exit 1; }
    bin="$tmp"
    case "$${url%%[?#]*}" in
      *.tar.gz)
        # Archive pinned above; take only the top-level regular file "halod".
        tar -xzf "$tmp" -C "$d" halod
        if [ -L "$d/halod" ] || [ ! -f "$d/halod" ]; then echo "halod in archive is not a regular file" >&2; exit 1; fi
        bin="$d/halod" ;;
    esac
    sudo install -d -o 0 -g 0 -m 0755 /usr/local/lib/halos /etc/halos /var/lib/halos
    sudo install -o 0 -g 0 -m 0755 "$bin" /usr/local/lib/halos/halod
    sudo install -o 0 -g 0 -m 0644 /dev/null /etc/halos/release.pub
    sudo tee /etc/halos/release.pub >/dev/null <<'HALOS_PUB'
    ${trimspace(var.pubkey_pem)}
    HALOS_PUB
    sudo install -o 0 -g 0 -m 0644 /dev/null /etc/halos/halod.yaml
    subject='${local.subject}'
    {
      printf 'registry: %s\norg: %s\nring: %s\npubkey: /etc/halos/release.pub\nos: linux\n' '${var.registry}' '${var.org}' '${var.ring}'
      if [ -n "$subject" ]; then printf 'subject: "%s"\n' "$subject"; fi
    } | sudo tee /etc/halos/halod.yaml >/dev/null
    sudo /usr/local/lib/halos/halod once --install
  EOT
}

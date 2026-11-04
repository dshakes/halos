terraform {
  required_providers {
    coder  = { source = "coder/coder" }
    docker = { source = "kreuzwerker/docker" }
  }
}
provider "docker" {}
data "coder_workspace" "me" {}
data "coder_workspace_owner" "me" {}

variable "registry" { type = string }
variable "org" { type = string }
variable "ring" { type = string }
variable "pubkey_pem" { type = string }
variable "other_pubkey_pem" { type = string }
variable "arch" { type = string } # docker daemon arch: amd64 | arm64
variable "tgz_url" { type = string }
variable "tgz_sha" { type = string } # sha256 of the archive for var.arch
variable "raw_url" { type = string }
variable "raw_sha" { type = string }
variable "evil_url" { type = string } # archive whose halod member is a symlink
variable "evil_sha" { type = string }
variable "image" { type = string }

# good = release archive (.tar.gz); goodraw = raw binary; badsha = wrong archive sha256;
# badkey = release not signed by the embedded key; badtar = pinned archive whose halod is a symlink
data "coder_parameter" "mode" {
  name    = "mode"
  type    = "string"
  default = "good"
  option {
    name  = "good"
    value = "good"
  }
  option {
    name  = "goodraw"
    value = "goodraw"
  }
  option {
    name  = "badsha"
    value = "badsha"
  }
  option {
    name  = "badkey"
    value = "badkey"
  }
  option {
    name  = "badtar"
    value = "badtar"
  }
}

locals {
  mode = data.coder_parameter.mode.value
  url  = local.mode == "goodraw" ? var.raw_url : local.mode == "badtar" ? var.evil_url : var.tgz_url
  sha0 = local.mode == "goodraw" ? var.raw_sha : local.mode == "badtar" ? var.evil_sha : var.tgz_sha
  sha  = local.mode == "badsha" ? "${substr(local.sha0, 0, 63)}${substr(local.sha0, 63, 1) == "0" ? "1" : "0"}" : local.sha0
}

resource "coder_agent" "main" {
  os   = "linux"
  arch = var.arch
}

module "halos" {
  source             = "./halos"
  agent_id           = coder_agent.main.id
  registry           = var.registry
  org                = var.org
  ring               = var.ring
  pubkey_pem         = local.mode == "badkey" ? var.other_pubkey_pem : var.pubkey_pem
  halod_url          = local.url
  halod_sha256_amd64 = local.sha
  halod_sha256_arm64 = local.sha
}

resource "docker_container" "ws" {
  count      = data.coder_workspace.me.start_count
  image      = var.image
  name       = "halos-uat-ws-${data.coder_workspace.me.id}"
  entrypoint = ["sh", "-c", coder_agent.main.init_script]
  env        = ["CODER_AGENT_TOKEN=${coder_agent.main.token}"]
  host {
    host = "host.docker.internal"
    ip   = "host-gateway"
  }
  labels {
    label = "halos-uat"
    value = "coder"
  }
}

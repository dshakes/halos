{{- define "halo.name" -}}{{ .Chart.Name }}{{- end -}}

{{- define "halo.fullname" -}}
{{- if .Values.fullnameOverride -}}{{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else if contains .Chart.Name .Release.Name -}}{{ .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- end -}}

{{/* component fullname: call with (list . "proxy") */}}
{{- define "halo.cname" -}}{{ printf "%s-%s" (include "halo.fullname" (index . 0)) (index . 1) | trunc 63 | trimSuffix "-" }}{{- end -}}

{{- define "halo.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "halo.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* selector labels: (list . "proxy") */}}
{{- define "halo.selector" -}}
app.kubernetes.io/name: {{ include "halo.name" (index . 0) }}
app.kubernetes.io/instance: {{ (index . 0).Release.Name }}
app.kubernetes.io/component: {{ index . 1 }}
{{- end -}}

{{- define "halo.serviceAccountName" -}}{{ default (include "halo.fullname" .) .Values.serviceAccount.name }}{{- end -}}

{{- define "halo.proxyServiceAccountName" -}}
{{- $sa := .Values.proxy.serviceAccount -}}
{{- if $sa.create -}}{{ default (include "halo.cname" (list . "proxy")) $sa.name }}
{{- else -}}{{ default (include "halo.serviceAccountName" .) $sa.name }}{{- end -}}
{{- end -}}

{{/* image: (list . imageValues defaultRepoName) ; digest wins over tag */}}
{{- define "halo.image" -}}
{{- $root := index . 0 -}}{{- $img := index . 1 -}}
{{- $reg := default $root.Values.image.registry $img.registry -}}
{{- if $img.digest -}}{{ printf "%s/%s@%s" $reg $img.repository $img.digest }}
{{- else -}}{{ printf "%s/%s:%s" $reg $img.repository (default $root.Chart.AppVersion $img.tag) }}{{- end -}}
{{- end -}}

{{- define "halo.pullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
{{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* topology spread: (list . "proxy") */}}
{{- define "halo.topologySpread" -}}
{{- $root := index . 0 -}}
{{- if $root.Values.topologySpread.enabled }}
topologySpreadConstraints:
{{- range $key := $root.Values.topologySpread.topologyKeys }}
  - maxSkew: {{ $root.Values.topologySpread.maxSkew }}
    topologyKey: {{ $key }}
    whenUnsatisfiable: {{ $root.Values.topologySpread.whenUnsatisfiable }}
    labelSelector:
      matchLabels:
        {{- include "halo.selector" (list $root (index $ 1)) | nindent 8 }}
{{- end }}
{{- end }}
{{- end -}}

{{/* git-sync container. (dict "root" . "name" "git-sync" "once" bool "link" "current" "dir" "/policy" "vol" "policy") */}}
{{- define "halo.gitsync" -}}
{{- $r := .root -}}{{- $g := $r.Values.policy.gitSync -}}
- name: {{ .name }}
  image: {{ include "halo.image" (list $r $g.image) }}
  imagePullPolicy: {{ $r.Values.image.pullPolicy }}
  args:
    - --repo={{ $g.repo }}
    - --ref={{ $g.ref }}
    - --root={{ .dir }}
    - --link={{ .link }}
    - --depth={{ $g.depth }}
    {{- if .once }}
    - --one-time
    {{- else }}
    - --period={{ $g.period }}
    {{- end }}
    {{- if eq $g.auth.type "ssh" }}
    - --ssh
    - --ssh-key-file=/etc/git-secret/ssh
    - --ssh-known-hosts-file=/etc/git-secret/known_hosts
    {{- else if eq $g.auth.type "token" }}
    - --username={{ $g.auth.username }}
    - --password-file=/etc/git-secret/password
    {{- end }}
  env:
    - {name: HOME, value: /tmp}
  securityContext: {{- toYaml $r.Values.securityContext | nindent 4 }}
  resources: {{- toYaml $g.resources | nindent 4 }}
  volumeMounts:
    - {name: {{ .vol }}, mountPath: {{ .dir }}}
    - {name: tmp, mountPath: /tmp}
    {{- if ne $g.auth.type "none" }}
    - {name: git-secret, mountPath: /etc/git-secret, readOnly: true}
    {{- end }}
{{- end -}}

{{- define "halo.gitsyncVolume" -}}
{{- $g := .Values.policy.gitSync -}}
{{- if ne $g.auth.type "none" }}
- name: git-secret
  secret:
    secretName: {{ required "policy.gitSync.auth.existingSecret is required when auth.type != none" $g.auth.existingSecret }}
    defaultMode: 0440
{{- end }}
{{- end -}}

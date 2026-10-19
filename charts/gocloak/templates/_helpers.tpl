{{- define "gocloak.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "gocloak.fullname" -}}
{{- if contains .Chart.Name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "gocloak.selectorLabels" -}}
app.kubernetes.io/name: {{ include "gocloak.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "gocloak.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "gocloak.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "gocloak.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "gocloak.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "gocloak.adminSecret" -}}
{{- default (printf "%s-admin" (include "gocloak.fullname" .)) .Values.admin.existingSecret }}
{{- end }}

{{- define "gocloak.dbSecret" -}}
{{- default (printf "%s-db" (include "gocloak.fullname" .)) .Values.database.existingSecret }}
{{- end }}

{{- define "gocloak.sqlite" -}}
{{- if eq .Values.database.vendor "sqlite" }}true{{ end }}
{{- end }}

{{- define "gocloak.validate" -}}
{{- if not (has .Values.database.vendor (list "sqlite" "postgres")) }}
{{- fail "database.vendor must be sqlite or postgres" }}
{{- end }}
{{- if and (include "gocloak.sqlite" .) (gt (int .Values.replicaCount) 1) }}
{{- fail "SQLite serves a single node: set replicaCount to 1 or use database.vendor postgres" }}
{{- end }}
{{- if and (eq .Values.database.vendor "postgres") (not .Values.database.url) }}
{{- fail "database.url is required with database.vendor postgres" }}
{{- end }}
{{- end }}

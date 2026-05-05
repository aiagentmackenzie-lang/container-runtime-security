{{/*
SecurityScarlet Runtime — Helm template helpers
*/}}

{{- define "scarlet-runtime.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "scarlet-runtime.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "scarlet-runtime.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "scarlet-runtime.labels" -}}
helm.sh/chart: {{ include "scarlet-runtime.chart" . }}
{{ include "scarlet-runtime.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "scarlet-runtime.selectorLabels" -}}
app.kubernetes.io/name: {{ include "scarlet-runtime.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "scarlet-runtime.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "scarlet-runtime.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
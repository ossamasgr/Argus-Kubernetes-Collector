{{- define "argus.name" -}}
{{- printf "%s-argus" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "argus.role" -}}
{{- printf "argus-read-%s" (printf "%s/%s" .Release.Namespace .Release.Name | sha256sum | trunc 16) -}}
{{- end -}}
{{- define "argus.labels" -}}
app.kubernetes.io/name: argus-collector
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

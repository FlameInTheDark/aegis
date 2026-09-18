{{- define "aegis.name" -}}{{ .Chart.Name }}{{- end -}}
{{- define "aegis.fullname" -}}{{ .Release.Name }}-{{ include "aegis.name" . }}{{- end -}}
{{- define "aegis.labels" -}}
app.kubernetes.io/name: {{ include "aegis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}
{{- define "aegis.image" -}}{{ .Values.image.repository }}/{{ .image }}:{{ .Values.image.tag }}{{- end -}}
{{- define "aegis.env" -}}
- name: AEGIS_ENV
  value: {{ .Values.config.env }}
- name: AEGIS_DATABASE_URL
  valueFrom: { secretKeyRef: { name: {{ .Release.Name }}-aegis-secret, key: database-url } }
- name: AEGIS_REDIS_URL
  value: {{ .Values.config.redisURL }}
- name: AEGIS_NATS_URL
  value: {{ .Values.config.natsURL }}
- name: AEGIS_CLICKHOUSE_URL
  value: {{ .Values.config.clickhouseURL }}
- name: AEGIS_JWT_SECRET
  valueFrom: { secretKeyRef: { name: {{ .Release.Name }}-aegis-secret, key: jwt-secret } }
{{- end -}}

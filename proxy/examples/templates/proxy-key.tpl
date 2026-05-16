{{- with secret "pki/issue/proxy" "common_name=proxy.local" "alt_names=proxy,proxy.internal,127.0.0.1" "ttl=24h" -}}
{{ .Data.private_key }}
{{- end }}



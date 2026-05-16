# Vault Agent configuration to render proxy TLS materials
# Copy to /etc/vault/vault-agent-proxy.hcl (example)

exit_after_auth = false
pid_file = "/run/vault-agent-proxy.pid"

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path   = "/etc/vault/proxy-role-id"
      secret_id_file_path = "/etc/vault/proxy-secret-id"
    }
  }
  sink "file" {
    config = {
      path = "/run/vault-agent/proxy-token"
    }
  }
}

template {
  source      = "/etc/vault/templates/proxy-cert.tpl"
  destination = "/run/proxy-certs/server.crt"
  perms       = "0640"
  left_delimiter  = "{{"
  right_delimiter = "}}"
  command     = "systemctl kill -s SIGHUP my-proxy.service"
}

template {
  source      = "/etc/vault/templates/proxy-key.tpl"
  destination = "/run/proxy-certs/server.key"
  perms       = "0600"
  left_delimiter  = "{{"
  right_delimiter = "}}"
  command     = "systemctl kill -s SIGHUP my-proxy.service"
}

template {
  source      = "/etc/vault/templates/proxy-ca.tpl"
  destination = "/run/proxy-certs/ca.crt"
  perms       = "0640"
  left_delimiter  = "{{"
  right_delimiter = "}}"
  command     = "systemctl kill -s SIGHUP my-proxy.service"
}

vault {
  address = "https://vault.example.com:8200"
  retry {
    num_retries = 5
  }
}



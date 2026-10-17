# The OpenBao of Keystone (docker-compose.yml). The setup wizard of Keystone initialises it; the static seal unseals it
# at every start with openbao/keys/unseal.key (install.sh makes it: keep a copy, without it the data cannot be read).
ui            = false
disable_mlock = true
api_addr      = "http://openbao:8200"
cluster_addr  = "http://openbao:8201"

storage "raft" {
  path    = "/openbao/data"
  node_id = "keystone-bao1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

seal "static" {
  current_key_id = "unseal-1"
  current_key    = "file:///openbao/keys/unseal.key"
}

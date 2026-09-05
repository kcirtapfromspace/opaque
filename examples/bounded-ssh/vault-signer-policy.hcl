# Install this policy on the broker's dedicated signer identity. It grants no
# CA administration, role mutation, host-certificate signing or key export.
path "ssh-client-signer/sign/fixture-health" {
  capabilities = ["update"]
}

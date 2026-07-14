#!/usr/bin/env bash

set -euo pipefail

usage() {
	cat <<'EOF'
Generate a local CA and a TLS server certificate for the Puppy HTTPS proxy.

Usage:
  generate-proxy-certs.sh [options]

Options:
  --output-dir DIR  Output directory (default: ./certs)
  --dns NAME        Add a DNS subject alternative name; may be repeated
  --ip ADDRESS      Add an IP subject alternative name; may be repeated
  --days NUMBER     Server certificate validity in days (default: 365)
  --force           Replace certificates previously generated in the output directory
  -h, --help        Show this help

The server certificate always includes DNS:localhost and IP:127.0.0.1.
The generated ca-cert.pem must be trusted by clients using the HTTPS proxy.
EOF
}

output_dir="./certs"
days=365
force=false
dns_names=("localhost")
ip_addresses=("127.0.0.1")

while (($# > 0)); do
	case "$1" in
	--output-dir)
		(($# >= 2)) || { echo "error: --output-dir requires a value" >&2; exit 2; }
		output_dir=$2
		shift 2
		;;
	--dns)
		(($# >= 2)) || { echo "error: --dns requires a value" >&2; exit 2; }
		dns_names+=("$2")
		shift 2
		;;
	--ip)
		(($# >= 2)) || { echo "error: --ip requires a value" >&2; exit 2; }
		ip_addresses+=("$2")
		shift 2
		;;
	--days)
		(($# >= 2)) || { echo "error: --days requires a value" >&2; exit 2; }
		days=$2
		shift 2
		;;
	--force)
		force=true
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "error: unknown option: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

command -v openssl >/dev/null 2>&1 || { echo "error: openssl is required" >&2; exit 1; }
[[ $days =~ ^[1-9][0-9]*$ ]] || { echo "error: --days must be a positive integer" >&2; exit 2; }
[[ -n $output_dir ]] || { echo "error: --output-dir must not be empty" >&2; exit 2; }

for name in "${dns_names[@]}"; do
	[[ $name =~ ^([A-Za-z0-9_*.-]+)$ ]] || { echo "error: invalid DNS name: $name" >&2; exit 2; }
done
for address in "${ip_addresses[@]}"; do
	[[ $address =~ ^[0-9A-Fa-f:.]+$ ]] || { echo "error: invalid IP address: $address" >&2; exit 2; }
done

files=(ca-cert.pem ca-key.pem proxy-cert.pem proxy-key.pem)
mkdir -p "$output_dir"
if [[ $force != true ]]; then
	for file in "${files[@]}"; do
		if [[ -e "$output_dir/$file" ]]; then
			echo "error: $output_dir/$file already exists; use --force to replace generated certificates" >&2
			exit 1
		fi
	done
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/puppy-certs.XXXXXX")
cleanup() {
	rm -rf "$work_dir"
}
trap cleanup EXIT

cat >"$work_dir/ca.conf" <<'EOF'
[req]
prompt = no
distinguished_name = distinguished_name
x509_extensions = v3_ca

[distinguished_name]
commonName = Puppy Local Proxy CA

[v3_ca]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

{
	cat <<'EOF'
[req]
prompt = no
distinguished_name = distinguished_name
req_extensions = request_extensions

[distinguished_name]
commonName = Puppy HTTPS Proxy

[request_extensions]
subjectAltName = @alternative_names

[v3_server]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @alternative_names

[alternative_names]
EOF
	index=1
	for name in "${dns_names[@]}"; do
		printf 'DNS.%d = %s\n' "$index" "$name"
		((index += 1))
	done
	index=1
	for address in "${ip_addresses[@]}"; do
		printf 'IP.%d = %s\n' "$index" "$address"
		((index += 1))
	done
} >"$work_dir/server.conf"

openssl genrsa -out "$work_dir/ca-key.pem" 3072 >/dev/null 2>&1
openssl req -x509 -new -sha256 \
	-key "$work_dir/ca-key.pem" \
	-out "$work_dir/ca-cert.pem" \
	-days 3650 \
	-config "$work_dir/ca.conf"

openssl genrsa -out "$work_dir/proxy-key.pem" 3072 >/dev/null 2>&1
openssl req -new -sha256 \
	-key "$work_dir/proxy-key.pem" \
	-out "$work_dir/proxy.csr" \
	-config "$work_dir/server.conf"
openssl x509 -req -sha256 \
	-in "$work_dir/proxy.csr" \
	-CA "$work_dir/ca-cert.pem" \
	-CAkey "$work_dir/ca-key.pem" \
	-CAcreateserial \
	-out "$work_dir/proxy-cert.pem" \
	-days "$days" \
	-extfile "$work_dir/server.conf" \
	-extensions v3_server >/dev/null

openssl verify -CAfile "$work_dir/ca-cert.pem" "$work_dir/proxy-cert.pem" >/dev/null
chmod 0600 "$work_dir/ca-key.pem" "$work_dir/proxy-key.pem"
chmod 0644 "$work_dir/ca-cert.pem" "$work_dir/proxy-cert.pem"

for file in "${files[@]}"; do
	mv -f "$work_dir/$file" "$output_dir/$file"
done

echo "Generated Puppy HTTPS proxy certificates in $output_dir"
echo "Trust $output_dir/ca-cert.pem on proxy clients."
echo "Keep $output_dir/ca-key.pem and $output_dir/proxy-key.pem private."

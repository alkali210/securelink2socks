module securelink2socks

go 1.26.3

require (
	github.com/n0madic/go-openvpn v0.0.0-20260704073850-12597991e312
	github.com/n0madic/go-openvpn/pkg/netstack v0.0.0-20260704073850-12597991e312
)

require (
	github.com/google/btree v1.1.3 // indirect
	github.com/n0madic/go-tun2net v0.0.0-20260607101155-baecdf85b64d // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	gvisor.dev/gvisor v0.0.0-20260603223238-3694902083d5 // indirect
)

replace github.com/n0madic/go-openvpn => ./third_party/go-openvpn

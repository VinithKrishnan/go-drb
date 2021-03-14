module crypto

go 1.14

replace ed25519 => ./ed25519

require (
	ed25519 v0.0.0-00010101000000-000000000000 // indirect
	github.com/cloudflare/bn256 v0.0.0-20201110172847-66a4f6353b47 // indirect
	github.com/consensys/gurvy v0.3.8 // indirect
	github.com/ethereum/go-ethereum v1.9.25
)

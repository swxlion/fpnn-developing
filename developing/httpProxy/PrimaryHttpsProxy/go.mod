module primaryServer

go 1.19

replace local/proxyServer => ./proxyServer

require local/proxyServer v0.0.0-00010101000000-000000000000

require (
	github.com/highras/fpnn-sdk-go v1.1.0 // indirect
	github.com/ugorji/go/codec v1.2.7 // indirect
)

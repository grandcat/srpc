all: protoc_internal_rpc

protoc_internal_rpc: pairing.proto
	protoc --go_out=plugins=grpc:. pairing.proto
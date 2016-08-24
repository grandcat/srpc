all: protoc_internal_rpc

protoc_internal_rpc: helloworld.proto
	protoc --go_out=plugins=grpc:. helloworld.proto
# $(MAKE) -C pairing all

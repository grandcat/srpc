// Code generated by protoc-gen-go.
// source: helloworld.proto
// DO NOT EDIT!

/*
Package helloworld is a generated protocol buffer package.

It is generated from these files:
	helloworld.proto

It has these top-level messages:
	HelloRequest
	CalenderDay
	HelloReply
*/
package helloworld

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// The request message containing the user's name.
type HelloRequest struct {
	Name  string       `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	Birth *CalenderDay `protobuf:"bytes,2,opt,name=birth" json:"birth,omitempty"`
}

func (m *HelloRequest) Reset()                    { *m = HelloRequest{} }
func (m *HelloRequest) String() string            { return proto.CompactTextString(m) }
func (*HelloRequest) ProtoMessage()               {}
func (*HelloRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *HelloRequest) GetBirth() *CalenderDay {
	if m != nil {
		return m.Birth
	}
	return nil
}

type CalenderDay struct {
	Day   int32 `protobuf:"varint,1,opt,name=day" json:"day,omitempty"`
	Month int32 `protobuf:"varint,2,opt,name=month" json:"month,omitempty"`
	Year  int32 `protobuf:"varint,3,opt,name=year" json:"year,omitempty"`
}

func (m *CalenderDay) Reset()                    { *m = CalenderDay{} }
func (m *CalenderDay) String() string            { return proto.CompactTextString(m) }
func (*CalenderDay) ProtoMessage()               {}
func (*CalenderDay) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

// The response message containing the greetings
type HelloReply struct {
	Message string `protobuf:"bytes,1,opt,name=message" json:"message,omitempty"`
}

func (m *HelloReply) Reset()                    { *m = HelloReply{} }
func (m *HelloReply) String() string            { return proto.CompactTextString(m) }
func (*HelloReply) ProtoMessage()               {}
func (*HelloReply) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func init() {
	proto.RegisterType((*HelloRequest)(nil), "helloworld.HelloRequest")
	proto.RegisterType((*CalenderDay)(nil), "helloworld.CalenderDay")
	proto.RegisterType((*HelloReply)(nil), "helloworld.HelloReply")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion3

// Client API for Greeter service

type GreeterClient interface {
	// Registers a new client certificate
	// rpc Register (RegisterRequest) returns (StatusReply) {}
	// Sends a greeting
	SayHello(ctx context.Context, in *HelloRequest, opts ...grpc.CallOption) (*HelloReply, error)
}

type greeterClient struct {
	cc *grpc.ClientConn
}

func NewGreeterClient(cc *grpc.ClientConn) GreeterClient {
	return &greeterClient{cc}
}

func (c *greeterClient) SayHello(ctx context.Context, in *HelloRequest, opts ...grpc.CallOption) (*HelloReply, error) {
	out := new(HelloReply)
	err := grpc.Invoke(ctx, "/helloworld.Greeter/SayHello", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Greeter service

type GreeterServer interface {
	// Registers a new client certificate
	// rpc Register (RegisterRequest) returns (StatusReply) {}
	// Sends a greeting
	SayHello(context.Context, *HelloRequest) (*HelloReply, error)
}

func RegisterGreeterServer(s *grpc.Server, srv GreeterServer) {
	s.RegisterService(&_Greeter_serviceDesc, srv)
}

func _Greeter_SayHello_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HelloRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GreeterServer).SayHello(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/helloworld.Greeter/SayHello",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GreeterServer).SayHello(ctx, req.(*HelloRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Greeter_serviceDesc = grpc.ServiceDesc{
	ServiceName: "helloworld.Greeter",
	HandlerType: (*GreeterServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SayHello",
			Handler:    _Greeter_SayHello_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: fileDescriptor0,
}

func init() { proto.RegisterFile("helloworld.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 245 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x6c, 0x50, 0xb1, 0x4e, 0xc3, 0x30,
	0x10, 0x25, 0x94, 0x50, 0xb8, 0x22, 0x51, 0x9d, 0x10, 0x58, 0xb0, 0xa0, 0x0c, 0x88, 0x85, 0x08,
	0x95, 0x9d, 0xa1, 0x20, 0x41, 0xb7, 0x62, 0x06, 0xe6, 0x2b, 0x39, 0xb5, 0x95, 0x9c, 0x38, 0x5c,
	0x8c, 0xc0, 0x7f, 0x4f, 0xed, 0xb6, 0xc2, 0x43, 0xb7, 0xf7, 0x9e, 0x9f, 0xdf, 0xbd, 0x3b, 0x18,
	0x2e, 0xd8, 0x18, 0xfb, 0x63, 0xc5, 0x54, 0x65, 0x2b, 0xd6, 0x59, 0x84, 0x7f, 0xa5, 0x78, 0x83,
	0x93, 0xd7, 0xc0, 0x34, 0x7f, 0x7d, 0x73, 0xe7, 0x10, 0xe1, 0xa0, 0xa1, 0x9a, 0x55, 0x76, 0x9d,
	0xdd, 0x1e, 0xeb, 0x88, 0xf1, 0x0e, 0xf2, 0xd9, 0x52, 0xdc, 0x42, 0xed, 0xaf, 0xc4, 0xc1, 0xe8,
	0xa2, 0x4c, 0x12, 0x9f, 0xc8, 0x70, 0x53, 0xb1, 0x3c, 0x93, 0xd7, 0x6b, 0x57, 0x31, 0x81, 0x41,
	0xa2, 0xe2, 0x10, 0x7a, 0x15, 0xf9, 0x18, 0x98, 0xeb, 0x00, 0xf1, 0x0c, 0xf2, 0xda, 0x36, 0x9b,
	0xbc, 0x5c, 0xaf, 0x49, 0x98, 0xec, 0x99, 0x44, 0xf5, 0xa2, 0x18, 0x71, 0x71, 0x03, 0xb0, 0x69,
	0xd7, 0x1a, 0x8f, 0x0a, 0xfa, 0x35, 0x77, 0x1d, 0xcd, 0xb7, 0xf5, 0xb6, 0x74, 0x34, 0x81, 0xfe,
	0x8b, 0x30, 0x3b, 0x16, 0x7c, 0x84, 0xa3, 0x77, 0xf2, 0xf1, 0x17, 0xaa, 0xb4, 0x69, 0xba, 0xe6,
	0xe5, 0xf9, 0x8e, 0x97, 0xd5, 0x88, 0x62, 0x6f, 0x7c, 0x0f, 0x57, 0x4b, 0x5b, 0xce, 0xa5, 0xfd,
	0x2c, 0xf9, 0x97, 0xea, 0xd6, 0x70, 0x97, 0x78, 0xc7, 0xa7, 0xd1, 0xfc, 0x11, 0xf0, 0x34, 0x1c,
	0x73, 0x9a, 0xcd, 0x0e, 0xe3, 0x55, 0x1f, 0xfe, 0x02, 0x00, 0x00, 0xff, 0xff, 0x4c, 0x70, 0xb8,
	0x17, 0x69, 0x01, 0x00, 0x00,
}

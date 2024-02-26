package mmrtesting

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azservicebus"
	"github.com/datatrails/go-datatrails-common/azbus"
	"github.com/opentracing/opentracing-go"
)

type TestCallCounter struct {
	MethodCalls map[string]int
}

type TestReceiverCallCounter struct {
	TestCallCounter
}
type TestSendCallCounter struct {
	TestCallCounter
}

func (r *TestCallCounter) IncMethodCall(name string) int {
	if r.MethodCalls == nil {
		r.MethodCalls = make(map[string]int)
	}

	cur, ok := r.MethodCalls[name]
	if !ok {
		r.MethodCalls[name] = 1
		return 1
	}
	r.MethodCalls[name] = cur + 1
	return cur + 1
}

func (r *TestCallCounter) Reset() {
	r.MethodCalls = make(map[string]int)
}

func (r *TestCallCounter) MethodCallCount(name string) int {

	cur, ok := r.MethodCalls[name]
	if !ok {
		return 0
	}
	return cur
}

func (r *TestReceiverCallCounter) Open() error                         { return nil }
func (r *TestReceiverCallCounter) Close(context.Context)               {}
func (r *TestReceiverCallCounter) ReceiveMessages(azbus.Handler) error { return nil }
func (r *TestReceiverCallCounter) String() string                      { return "test receiver" }

// Listener interface
func (r *TestReceiverCallCounter) Listen() error                  { return nil }
func (r *TestReceiverCallCounter) Shutdown(context.Context) error { return nil }

func (r *TestReceiverCallCounter) GetAZClient() azbus.AZClient { return azbus.AZClient{} }

func (s *TestSendCallCounter) Send(ctx context.Context, msg []byte, opts ...azbus.OutMessageOption) error {
	s.IncMethodCall("Send")
	return nil
}

func (s *TestSendCallCounter) Open() error { return nil }
func (s *TestSendCallCounter) SendMsg(context.Context, azbus.OutMessage, ...azbus.OutMessageOption) error {
	s.IncMethodCall("SendMsg")
	return nil
}
func (s *TestSendCallCounter) Close(context.Context)       {}
func (s *TestSendCallCounter) String() string              { return "testSender" }
func (s *TestSendCallCounter) GetAZClient() azbus.AZClient { return azbus.AZClient{} }

func (*TestSendCallCounter) UpdateSendingMesssageForSpan(
	ctx context.Context, message *azservicebus.Message, span opentracing.Span) {
}

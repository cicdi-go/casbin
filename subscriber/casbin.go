package subscriber

import (
	"context"
	"github.com/micro/go-log"

	casbin "github.com/cicdi-go/casbin/proto/casbin"
)

type Casbin struct{}

func (e *Casbin) Handle(ctx context.Context, msg *casbin.Message) error {
	log.Log("Handler Received message: ", msg.Say)
	return nil
}

func Handler(ctx context.Context, msg *casbin.Message) error {
	log.Log("Function Received message: ", msg.Say)
	return nil
}

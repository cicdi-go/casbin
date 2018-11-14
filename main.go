package main

import (
	"github.com/micro/go-log"
	"github.com/micro/go-micro"
	"github.com/cicdi-go/casbin/handler"
	"github.com/cicdi-go/casbin/subscriber"

	casbin "github.com/cicdi-go/casbin/proto/casbin"
)

func main() {
	// New Service
	service := micro.NewService(
		micro.Name("go.micro.srv.casbin"),
		micro.Version("latest"),
	)

	// Initialise service
	service.Init()

	// Register Handler
	casbin.RegisterCasbinHandler(service.Server(), new(handler.Server))

	// Register Struct as Subscriber
	micro.RegisterSubscriber("go.micro.srv.casbin", service.Server(), new(subscriber.Casbin))

	// Register Function as Subscriber
	micro.RegisterSubscriber("go.micro.srv.casbin", service.Server(), subscriber.Handler)

	// Run service
	if err := service.Run(); err != nil {
		log.Fatal(err)
	}
}

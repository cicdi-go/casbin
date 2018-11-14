// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handler

import (
	"errors"

	"context"
	"github.com/casbin/casbin"
	pb "github.com/cicdi-go/casbin/proto/casbin"
	"github.com/casbin/casbin/persist"
)

// Server is used to implement proto.CasbinServer.
type Server struct {
	enforcerMap map[int]*casbin.Enforcer
	adapterMap  map[int]persist.Adapter
}

func NewServer() *Server {
	s := Server{}

	s.enforcerMap = map[int]*casbin.Enforcer{}
	s.adapterMap = map[int]persist.Adapter{}

	return &s
}

func (s *Server) getEnforcer(handle int) (*casbin.Enforcer, error) {
	if _, ok := s.enforcerMap[handle]; ok {
		return s.enforcerMap[handle], nil
	} else {
		return nil, errors.New("enforcer not found")
	}
}

func (s *Server) getAdapter(handle int) (persist.Adapter, error) {
	if _, ok := s.adapterMap[handle]; ok {
		return s.adapterMap[handle], nil
	} else {
		return nil, errors.New("adapter not found")
	}
}

func (s *Server) addEnforcer(e *casbin.Enforcer) int {
	cnt := len(s.enforcerMap)
	s.enforcerMap[cnt] = e
	return cnt
}

func (s *Server) addAdapter(a persist.Adapter) int {
	cnt := len(s.adapterMap)
	s.adapterMap[cnt] = a
	return cnt
}

func (s *Server) NewEnforcer(ctx context.Context, in *pb.NewEnforcerRequest, out *pb.NewEnforcerReply) error {
	var a persist.Adapter
	var e *casbin.Enforcer

	if in.AdapterHandle != -1 {
		var err error
		a, err = s.getAdapter(int(in.AdapterHandle))
		if err != nil {
			out = &pb.NewEnforcerReply{Handler: 0}
			return err
		}
	}

	if a == nil {
		e = casbin.NewEnforcer(casbin.NewModel(in.ModelText))
	} else {
		e = casbin.NewEnforcer(casbin.NewModel(in.ModelText), a)
	}
	h := s.addEnforcer(e)

	out = &pb.NewEnforcerReply{Handler: int32(h)}
	return nil
}

func (s *Server) NewAdapter(ctx context.Context, in *pb.NewAdapterRequest, out *pb.NewAdapterReply) error {
	a, err := newAdapter(in)
	if err != nil {
		out = nil
		return err
	}

	h := s.addAdapter(a)

	out = &pb.NewAdapterReply{Handler: int32(h)}
	return nil
}

func (s *Server) Enforce(ctx context.Context, in *pb.EnforceRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		out = &pb.BoolReply{Res: false}
		return err
	}

	params := make([]interface{}, 0, len(in.Params))

	m := e.GetModel()["m"]["m"]
	sourceValue := m.Value

	for index := range in.Params {
		param := parseAbacParam(in.Params[index], m)
		params = append(params, param)
	}

	res := e.Enforce(params...)

	m.Value = sourceValue

	out = &pb.BoolReply{Res: res}
	return nil
}

func (s *Server) LoadPolicy(ctx context.Context, in *pb.EmptyRequest, out *pb.EmptyReply) error {
	e, err := s.getEnforcer(int(in.Handler))
	if err != nil {
		out = &pb.EmptyReply{}
		return err
	}

	err = e.LoadPolicy()

	out = &pb.EmptyReply{}
	return err
}

func (s *Server) SavePolicy(ctx context.Context, in *pb.EmptyRequest, out *pb.EmptyReply) error {
	e, err := s.getEnforcer(int(in.Handler))
	if err != nil {
		out = &pb.EmptyReply{}
		return err
	}

	err = e.SavePolicy()

	out = &pb.EmptyReply{}
	return err
}

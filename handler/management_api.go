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
	"context"
	pb "github.com/cicdi-go/casbin/proto/casbin"
)

func (s *Server) wrapPlainPolicy(policy [][]string) *pb.Array2DReply {
	if len(policy) == 0 {
		return &pb.Array2DReply{}
	}

	policyReply := &pb.Array2DReply{}
	policyReply.D2 = make([]*pb.Array2DReplyD, len(policy))
	for e := range policy {
		policyReply.D2[e] = &pb.Array2DReplyD{D1: policy[e]}
	}

	return policyReply
}

// GetAllSubjects gets the list of subjects that show up in the current policy.
func (s *Server) GetAllSubjects(ctx context.Context, in *pb.EmptyRequest, out *pb.ArrayReply) error {
	return s.GetAllNamedSubjects(ctx, &pb.SimpleGetRequest{EnforcerHandler: in.Handler, PType: "p"}, out)
}

// GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
func (s *Server) GetAllNamedSubjects(ctx context.Context, in *pb.SimpleGetRequest, out *pb.ArrayReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.ArrayReply{Array: e.GetModel().GetValuesForFieldInPolicy("p", in.PType, 0)}
	return nil
}

// GetAllObjects gets the list of objects that show up in the current policy.
func (s *Server) GetAllObjects(ctx context.Context, in *pb.EmptyRequest, out *pb.ArrayReply) error {
	return s.GetAllNamedObjects(ctx, &pb.SimpleGetRequest{EnforcerHandler: in.Handler, PType: "p"}, out)
}

// GetAllNamedObjects gets the list of objects that show up in the current named policy.
func (s *Server) GetAllNamedObjects(ctx context.Context, in *pb.SimpleGetRequest, out *pb.ArrayReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.ArrayReply{Array: e.GetModel().GetValuesForFieldInPolicy("p", in.PType, 1)}
	return nil
}

// GetAllActions gets the list of actions that show up in the current policy.
func (s *Server) GetAllActions(ctx context.Context, in *pb.EmptyRequest, out *pb.ArrayReply) error {
	return s.GetAllNamedActions(ctx, &pb.SimpleGetRequest{EnforcerHandler: in.Handler, PType: "p"}, out)
}

// GetAllNamedActions gets the list of actions that show up in the current named policy.
func (s *Server) GetAllNamedActions(ctx context.Context, in *pb.SimpleGetRequest, out *pb.ArrayReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.ArrayReply{Array: e.GetModel().GetValuesForFieldInPolicy("p", in.PType, 2)}
	return nil
}

// GetAllRoles gets the list of roles that show up in the current policy.
func (s *Server) GetAllRoles(ctx context.Context, in *pb.EmptyRequest, out *pb.ArrayReply) error {
	return s.GetAllNamedRoles(ctx, &pb.SimpleGetRequest{EnforcerHandler: in.Handler, PType: "g"}, out)
}

// GetAllNamedRoles gets the list of roles that show up in the current named policy.
func (s *Server) GetAllNamedRoles(ctx context.Context, in *pb.SimpleGetRequest, out *pb.ArrayReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.ArrayReply{Array: e.GetModel().GetValuesForFieldInPolicy("g", in.PType, 1)}
	return nil
}

// GetPolicy gets all the authorization rules in the policy.
func (s *Server) GetPolicy(ctx context.Context, in *pb.EmptyRequest, out *pb.Array2DReply) error {
	return s.GetNamedPolicy(ctx, &pb.PolicyRequest{EnforcerHandler: in.Handler, PType: "p"}, out)
}

// GetNamedPolicy gets all the authorization rules in the named policy.
func (s *Server) GetNamedPolicy(ctx context.Context, in *pb.PolicyRequest, out *pb.Array2DReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = s.wrapPlainPolicy(e.GetModel().GetPolicy("p", in.PType))
	return nil
}

// GetFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
func (s *Server) GetFilteredPolicy(ctx context.Context, in *pb.FilteredPolicyRequest, out *pb.Array2DReply) error {
	in.PType = "p"

	return s.GetFilteredNamedPolicy(ctx, in, out)
}

// GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
func (s *Server) GetFilteredNamedPolicy(ctx context.Context, in *pb.FilteredPolicyRequest, out *pb.Array2DReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = s.wrapPlainPolicy(e.GetModel().GetFilteredPolicy("p", in.PType, int(in.FieldIndex), in.FieldValues...))
	return nil
}

// GetGroupingPolicy gets all the role inheritance rules in the policy.
func (s *Server) GetGroupingPolicy(ctx context.Context, in *pb.EmptyRequest, out *pb.Array2DReply) error {
	return s.GetNamedGroupingPolicy(ctx, &pb.PolicyRequest{EnforcerHandler: in.Handler, PType: "g"}, out)
}

// GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
func (s *Server) GetNamedGroupingPolicy(ctx context.Context, in *pb.PolicyRequest, out *pb.Array2DReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = s.wrapPlainPolicy(e.GetModel().GetPolicy("g", in.PType))
	return nil
}

// GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
func (s *Server) GetFilteredGroupingPolicy(ctx context.Context, in *pb.FilteredPolicyRequest, out *pb.Array2DReply) error {
	in.PType = "g"

	return s.GetFilteredNamedGroupingPolicy(ctx, in, out)
}

// GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
func (s *Server) GetFilteredNamedGroupingPolicy(ctx context.Context, in *pb.FilteredPolicyRequest, out *pb.Array2DReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = s.wrapPlainPolicy(e.GetModel().GetFilteredPolicy("g", in.PType, int(in.FieldIndex), in.FieldValues...))
	return nil
}

// HasPolicy determines whether an authorization rule exists.
func (s *Server) HasPolicy(ctx context.Context, in *pb.PolicyRequest, out *pb.BoolReply) error {
	return s.HasNamedPolicy(ctx, in, out)
}

// HasNamedPolicy determines whether a named authorization rule exists.
func (s *Server) HasNamedPolicy(ctx context.Context, in *pb.PolicyRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.GetModel().HasPolicy("p", in.PType, in.Params)}
	return nil
}

// HasGroupingPolicy determines whether a role inheritance rule exists.
func (s *Server) HasGroupingPolicy(ctx context.Context, in *pb.PolicyRequest, out *pb.BoolReply) error {
	in.PType = "g"

	return s.HasNamedGroupingPolicy(ctx, in, out)
}

// HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
func (s *Server) HasNamedGroupingPolicy(ctx context.Context, in *pb.PolicyRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.GetModel().HasPolicy("g", in.PType, in.Params)}
	return nil
}

func (s *Server) AddPolicy(ctx context.Context, in *pb.PolicyRequest, out *pb.BoolReply) error {
	in.PType = "p"

	return s.AddNamedPolicy(ctx, in, out)
}

func (s *Server) AddNamedPolicy(ctx context.Context, in *pb.PolicyRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.AddNamedPolicy(in.PType, in.Params)}
	return err
}

func (s *Server) RemovePolicy(ctx context.Context, in *pb.PolicyRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	res := e.RemovePolicy(in.Params)

	out = &pb.BoolReply{Res: res}
	return err
}

func (s *Server) RemoveNamedPolicy(ctx context.Context, in *pb.PolicyRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	res := e.RemoveNamedPolicy(in.PType, in.Params)

	out = &pb.BoolReply{Res: res}
	return err
}

// RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
func (s *Server) RemoveFilteredPolicy(ctx context.Context, in *pb.FilteredPolicyRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.RemoveFilteredNamedPolicy("p", int(in.FieldIndex), in.FieldValues...)}
	return nil
}

// RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
func (s *Server) RemoveFilteredNamedPolicy(ctx context.Context, in *pb.FilteredPolicyRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.RemoveFilteredNamedPolicy(in.PType, int(in.FieldIndex), in.FieldValues...)}
	return nil
}

// AddGroupingPolicy adds a role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (s *Server) AddGroupingPolicy(ctx context.Context, in *pb.PolicyRequest, out *pb.BoolReply) error {
	in.PType = "g"

	return s.AddNamedGroupingPolicy(ctx, in, out)
}

// AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (s *Server) AddNamedGroupingPolicy(ctx context.Context, in *pb.PolicyRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.AddNamedGroupingPolicy(in.PType, in.Params)}
	return nil
}

// RemoveGroupingPolicy removes a role inheritance rule from the current policy.
func (s *Server) RemoveGroupingPolicy(ctx context.Context, in *pb.PolicyRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.RemoveNamedGroupingPolicy("g", in.Params)}
	return nil
}

// RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
func (s *Server) RemoveNamedGroupingPolicy(ctx context.Context, in *pb.PolicyRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.RemoveNamedGroupingPolicy(in.PType, in.Params)}
	return nil
}

// RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
func (s *Server) RemoveFilteredGroupingPolicy(ctx context.Context, in *pb.FilteredPolicyRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.RemoveFilteredNamedGroupingPolicy("g", int(in.FieldIndex), in.FieldValues...)}
	return nil
}

// RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
func (s *Server) RemoveFilteredNamedGroupingPolicy(ctx context.Context, in *pb.FilteredPolicyRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.RemoveFilteredNamedGroupingPolicy(in.PType, int(in.FieldIndex), in.FieldValues...)}
	return nil
}

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

// GetRolesForUser gets the roles that a user has.
func (s *Server) GetRolesForUser(ctx context.Context, in *pb.UserRoleRequest, out *pb.ArrayReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	res, _ := e.GetModel()["g"]["g"].RM.GetRoles(in.User)

	out = &pb.ArrayReply{Array: res}
	return nil
}

// GetUsersForRole gets the users that has a role.
func (s *Server) GetUsersForRole(ctx context.Context, in *pb.UserRoleRequest, out *pb.ArrayReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	res, _ := e.GetModel()["g"]["g"].RM.GetUsers(in.User)

	out = &pb.ArrayReply{Array: res}
	return nil
}

// HasRoleForUser determines whether a user has a role.
func (s *Server) HasRoleForUser(ctx context.Context, in *pb.UserRoleRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	roles := e.GetRolesForUser(in.User)

	for _, r := range roles {
		if r == in.Role {
			out = &pb.BoolReply{Res: true}
			return nil
		}
	}

	out = &pb.BoolReply{}
	return nil
}

// AddRoleForUser adds a role for a user.
// Returns false if the user already has the role (aka not affected).
func (s *Server) AddRoleForUser(ctx context.Context, in *pb.UserRoleRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.AddGroupingPolicy(in.User, in.Role)}
	return nil
}

// DeleteRoleForUser deletes a role for a user.
// Returns false if the user does not have the role (aka not affected).
func (s *Server) DeleteRoleForUser(ctx context.Context, in *pb.UserRoleRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.RemoveGroupingPolicy(in.User, in.Role)}
	return nil
}

// DeleteRolesForUser deletes all roles for a user.
// Returns false if the user does not have any roles (aka not affected).
func (s *Server) DeleteRolesForUser(ctx context.Context, in *pb.UserRoleRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.RemoveFilteredGroupingPolicy(0, in.User)}
	return nil
}

// DeleteUser deletes a user.
// Returns false if the user does not exist (aka not affected).
func (s *Server) DeleteUser(ctx context.Context, in *pb.UserRoleRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.RemoveFilteredGroupingPolicy(0, in.User)}
	return nil
}

// DeleteRole deletes a role.
func (s *Server) DeleteRole(ctx context.Context, in *pb.UserRoleRequest, out *pb.EmptyReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	e.RemoveFilteredGroupingPolicy(1, in.Role)
	e.RemoveFilteredPolicy(0, in.Role)

	out = &pb.EmptyReply{}
	return nil
}

// DeletePermission deletes a permission.
// Returns false if the permission does not exist (aka not affected).
func (s *Server) DeletePermission(ctx context.Context, in *pb.PermissionRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.RemoveFilteredPolicy(1, in.Permissions...)}
	return nil
}

// AddPermissionForUser adds a permission for a user or role.
// Returns false if the user or role already has the permission (aka not affected).
func (s *Server) AddPermissionForUser(ctx context.Context, in *pb.PermissionRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.AddPolicy(s.convertPermissions(in.User, in.Permissions...)...)}
	return nil
}

// DeletePermissionForUser deletes a permission for a user or role.
// Returns false if the user or role does not have the permission (aka not affected).
func (s *Server) DeletePermissionForUser(ctx context.Context, in *pb.PermissionRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.RemovePolicy(s.convertPermissions(in.User, in.Permissions...)...)}
	return nil
}

// DeletePermissionsForUser deletes permissions for a user or role.
// Returns false if the user or role does not have any permissions (aka not affected).
func (s *Server) DeletePermissionsForUser(ctx context.Context, in *pb.PermissionRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.RemoveFilteredPolicy(0, in.User)}
	return nil
}

// GetPermissionsForUser gets permissions for a user or role.
func (s *Server) GetPermissionsForUser(ctx context.Context, in *pb.PermissionRequest, out *pb.Array2DReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = s.wrapPlainPolicy(e.GetFilteredPolicy(0, in.User))
	return nil
}

// HasPermissionForUser determines whether a user has a permission.
func (s *Server) HasPermissionForUser(ctx context.Context, in *pb.PermissionRequest, out *pb.BoolReply) error {
	e, err := s.getEnforcer(int(in.EnforcerHandler))
	if err != nil {
		return err
	}

	out = &pb.BoolReply{Res: e.HasPolicy(s.convertPermissions(in.User, in.Permissions...)...)}
	return nil
}

func (s *Server) convertPermissions(user string, permissions ...string) []interface{} {
	params := make([]interface{}, 0, len(permissions)+1)
	params = append(params, user)
	for _, perm := range permissions {
		params = append(params, perm)
	}

	return params
}

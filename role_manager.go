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

package oktarolemanager

import (
	"errors"

	"github.com/casbin/casbin/rbac"
	"github.com/casbin/casbin/util"
	"github.com/chrismalek/oktasdk-go/okta"
)

type RoleManager struct {
	orgName               string
	apiToken              string
	isProductionOrPreview bool
	client                *okta.Client
}

// NewRoleManager is the constructor of an Okta RoleManager instance.
// orgName is your organization name.
// apiToken is the token you created in the Admin portal.
// For example, if your domain name is like: dev-123456.oktapreview.com,
// then your orgName is dev-123456, isProductionOrPreview is false.
// If your domain name is like: company_name.okta.com, then your orgName
// is company_name, isProductionOrPreview is true.
func NewRoleManager(orgName string, apiToken string, isProductionOrPreview bool) rbac.RoleManager {
	rm := RoleManager{}
	rm.orgName = orgName
	rm.apiToken = apiToken
	rm.isProductionOrPreview = isProductionOrPreview

	rm.client = okta.NewClient(nil, orgName, apiToken, isProductionOrPreview)
	util.LogPrintf("Client Base URL: %v\n\n", rm.client.BaseURL)

	return &rm
}

//func (rm *RoleManager) listUsers() {
//	userFilter := &okta.UserListFilterOptions{}
//	userFilter.GetAllPages = true
//	userFilter.StatusEqualTo = okta.UserStatusActive
//
//	allUsers, response, err := rm.client.Users.ListWithFilter(userFilter)
//
//	if err != nil {
//		util.LogPrintf("Response Error %+v\n\t URL used:%v\n", err, response.Request.URL.String())
//	}
//
//	util.LogPrintf("len(all_users) = %v\n", len(allUsers))
//}

func (rm *RoleManager) getOktaUserByLogin(login string) (*okta.User, error) {
	userFilter := &okta.UserListFilterOptions{}
	userFilter.LoginEqualTo = login

	allUsers, _, err := rm.client.Users.ListWithFilter(userFilter)

	if err != nil {
		return nil, err
	}

	if len(allUsers) == 0 {
		return nil, errors.New("error: Okta user not found")
	} else if len(allUsers) > 1 {
		return nil, errors.New("error: multiple Okta users with the same login found")
	}

	return &allUsers[0], nil
}

func (rm *RoleManager) getOktaUserGroups(user *okta.User) ([]string, error) {
	res := []string{}

	_, err := rm.client.Users.PopulateGroups(user)
	if err != nil {
		return nil, err
	}

	for _,  group := range user.Groups {
		res = append(res, group.Profile.Name)
	}
	return res, nil
}

func (rm *RoleManager) getOktaGroupByName(name string) (*okta.Group, error) {
	groupFilter := &okta.GroupFilterOptions{}
	groupFilter.GetAllPages = true
	groupFilter.NameStartsWith = name

	allGroups, _, err := rm.client.Groups.ListWithFilter(groupFilter)

	if err != nil {
		return nil, err
	}

	if len(allGroups) == 0 {
		return nil, errors.New("error: Okta group not found")
	} else if len(allGroups) > 1 {
		return nil, errors.New("error: multiple Okta groups with the same name found")
	}

	return &allGroups[0], nil
}

func (rm *RoleManager) getOktaGroupUsers(group *okta.Group) ([]string, error) {
	res := []string{}

	groupUserFilter := new(okta.GroupUserFilterOptions)
	groupUserFilter.GetAllPages = true

	users, _, err := rm.client.Groups.GetUsers(group.ID, groupUserFilter)
	if err != nil {
		return nil, err
	}

	for _,  user := range users {
		if user.Status == "ACTIVE" {
			res = append(res, user.Profile.Login)
		}
	}
	return res, nil
}

// Clear clears all stored data and resets the role manager to the initial state.
func (rm *RoleManager) Clear() error {
	return nil
}

// AddLink adds the inheritance link between role: name1 and role: name2.
// domain is not used.
func (rm *RoleManager) AddLink(name1 string, name2 string, domain ...string) error {
	return errors.New("not implemented")
}

// DeleteLink deletes the inheritance link between role: name1 and role: name2.
// domain is not used.
func (rm *RoleManager) DeleteLink(name1 string, name2 string, domain ...string) error {
	return errors.New("not implemented")
}

// HasLink determines whether role: name1 inherits role: name2.
// domain is not used.
func (rm *RoleManager) HasLink(name1 string, name2 string, domain ...string) (bool, error) {
	if len(domain) >= 1 {
		return false, errors.New("error: domain should not be used")
	}

	roles, err := rm.GetRoles(name1)
	if err != nil {
		return false, err
	}

	for _, role := range roles {
		if role == name2 {
			return true, nil
		}
	}
	return false, nil
}

// GetRoles gets the roles that a subject inherits.
// domain is not used.
func (rm *RoleManager) GetRoles(name string, domain ...string) ([]string, error) {
	if len(domain) >= 1 {
		return nil, errors.New("error: domain should not be used")
	}

	user, err := rm.getOktaUserByLogin(name)
	if err != nil {
		return nil, err
	}

	return rm.getOktaUserGroups(user)
}

// GetUsers gets the users that inherits a subject.
// domain is not used.
func (rm *RoleManager) GetUsers(name string, domain ...string) ([]string, error) {
	if len(domain) >= 1 {
		return nil, errors.New("error: domain should not be used")
	}

	group, err := rm.getOktaGroupByName(name)
	if err != nil {
		return nil, err
	}

	return rm.getOktaGroupUsers(group)
}

// PrintRoles prints all the roles to log.
func (rm *RoleManager) PrintRoles() error {
	return errors.New("not implemented")
}

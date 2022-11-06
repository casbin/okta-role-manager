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
	"context"
	"errors"
	"fmt"

	"github.com/casbin/casbin/v2/log"
	"github.com/casbin/casbin/v2/rbac"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

type RoleManager struct {
	client *okta.Client
}

// NewRoleManager is the constructor of an Okta RoleManager instance.
// oktaDomain is the domain for your organization on Okta.
// If https://dev-123456.okta.com is your org URL, then dev-17237792.okta.com is oktaDomain.
// apiToken is the token you created in the Admin portal.
func NewRoleManager(oktaDomain string, apiToken string, isProduction bool) rbac.RoleManager {
	_, client, err := okta.NewClient(
		context.TODO(),
		okta.WithOrgUrl(fmt.Sprintf("https://%s", oktaDomain)),
		okta.WithToken(apiToken),
	)
	if err != nil {
		panic(err)
	}
	return RoleManager{client}
}

func (rm RoleManager) getOktaUserByLogin(ctx context.Context, login string) (*okta.User, error) {
	user, _, err := rm.client.User.GetUser(ctx, login)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, errors.New("error: Okta user not found")
	}
	return user, nil
}

func (rm RoleManager) getOktaUserGroups(ctx context.Context, user *okta.User) ([]string, error) {
	res := []string{}

	groups, _, err := rm.client.User.ListUserGroups(ctx, user.Id)
	if err != nil {
		return nil, err
	}

	for _, group := range groups {
		res = append(res, group.Profile.Name)
	}
	return res, nil
}

func (rm RoleManager) getOktaGroupByName(ctx context.Context, name string) (*okta.Group, error) {
	allGroups, _, err := rm.client.Group.ListGroups(ctx, query.NewQueryParams(query.WithQ(name)))
	if err != nil {
		return nil, err
	}

	if len(allGroups) == 0 {
		return nil, errors.New("error: Okta group not found")
	} else if len(allGroups) > 1 {
		return nil, errors.New("error: multiple Okta groups with the same name found")
	}

	return allGroups[0], nil
}

func (rm RoleManager) getOktaGroupUsers(ctx context.Context, group *okta.Group) ([]string, error) {
	res := []string{}

	filter := query.NewQueryParams(query.WithFilter("status eq \"ACTIVE\""))
	users, _, err := rm.client.Group.ListGroupUsers(ctx, group.Id, filter)
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		res = append(res, (*user.Profile)["login"].(string))
	}
	return res, nil
}

// Clear clears all stored data and resets the role manager to the initial state.
func (rm RoleManager) Clear() error {
	return nil
}

// AddLink adds the inheritance link between role: name1 and role: name2.
// domain is not used.
func (rm RoleManager) AddLink(name1 string, name2 string, domain ...string) error {
	return errors.New("not implemented")
}

// DeleteLink deletes the inheritance link between role: name1 and role: name2.
// domain is not used.
func (rm RoleManager) DeleteLink(name1 string, name2 string, domain ...string) error {
	return errors.New("not implemented")
}

// HasLink determines whether role: name1 inherits role: name2.
// domain is not used.
func (rm RoleManager) HasLink(name1 string, name2 string, domain ...string) (bool, error) {
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
func (rm RoleManager) GetRoles(name string, domain ...string) ([]string, error) {
	if len(domain) >= 1 {
		return nil, errors.New("error: domain should not be used")
	}

	user, err := rm.getOktaUserByLogin(context.Background(), name)
	if err != nil {
		return nil, err
	}

	return rm.getOktaUserGroups(context.Background(), user)
}

// GetUsers gets the users that inherits a subject.
// domain is not used.
func (rm RoleManager) GetUsers(name string, domain ...string) ([]string, error) {
	if len(domain) >= 1 {
		return nil, errors.New("error: domain should not be used")
	}

	group, err := rm.getOktaGroupByName(context.Background(), name)
	if err != nil {
		return nil, err
	}

	return rm.getOktaGroupUsers(context.Background(), group)
}

// PrintRoles prints all the roles to log.
func (rm RoleManager) PrintRoles() error {
	return errors.New("not implemented")
}

// BuildRelationship is deprecated.
func (rm RoleManager) BuildRelationship(name1, name2 string, domain ...string) error {
	return errors.New("not implemented")
}

func (rm RoleManager) GetAllDomains() ([]string, error) {
	return nil, errors.New("not implemented")
}

func (rm RoleManager) GetDomains(name string) ([]string, error) {
	return nil, errors.New("not implemented")
}

func (rm RoleManager) SetLogger(logger log.Logger) {
	return
}

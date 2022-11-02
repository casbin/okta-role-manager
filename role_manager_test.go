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
	"log"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/rbac"
	"github.com/casbin/casbin/v2/util"
)

func testEnforce(t *testing.T, e *casbin.Enforcer, sub string, obj interface{}, act string, res bool) {
	t.Helper()
	r, err := e.Enforce(sub, obj, act)
	if err != nil {
		t.Errorf("%s, %v, %s: error is %s, supposed to be nil", sub, obj, act, err.Error())
	}
	if r != res {
		t.Errorf("%s, %v, %s: %t, supposed to be %t", sub, obj, act, !res, res)
	}
}

func testRole(t *testing.T, rm rbac.RoleManager, name1 string, name2 string, res bool) {
	t.Helper()
	myRes, _ := rm.HasLink(name1, name2)
	log.Printf("%s, %s: %t", name1, name2, myRes)

	if myRes != res {
		t.Errorf("%s < %s: %t, supposed to be %t", name1, name2, !res, res)
	}
}

func testPrintRoles(t *testing.T, rm rbac.RoleManager, name string, res []string) {
	t.Helper()
	myRes, _ := rm.GetRoles(name)
	log.Printf("%s: %s", name, myRes)

	if !util.ArrayEquals(myRes, res) {
		t.Errorf("%s: %s, supposed to be %s", name, myRes, res)
	}
}

func testPrintUsers(t *testing.T, rm rbac.RoleManager, name string, res []string) {
	t.Helper()
	myRes, _ := rm.GetUsers(name)
	log.Printf("%s: %s", name, myRes)

	if !util.ArrayEquals(myRes, res) {
		t.Errorf("%s: %s, supposed to be %s", name, myRes, res)
	}
}

func TestRole(t *testing.T) {
	rm := NewRoleManager("dev-000000", "your_api_token", false)

	// Current role inheritance tree:
	//           Everyone     Admin
	//         /          \  /
	// alice@test.com    bob@test.com

	// Note: you need to set this role inheritance in your Okta Admin portal
	// before running this test.

	testRole(t, rm, "alice@test.com", "Everyone", true)
	testRole(t, rm, "bob@test.com", "Everyone", true)
	testRole(t, rm, "alice@test.com", "Admin", false)
	testRole(t, rm, "bob@test.com", "Admin", true)

	testPrintRoles(t, rm, "alice@test.com", []string{"Everyone"})
	testPrintRoles(t, rm, "bob@test.com", []string{"Everyone", "Admin"})

	testPrintUsers(t, rm, "Everyone", []string{"alice@test.com", "bob@test.com"})
	testPrintUsers(t, rm, "Admin", []string{"bob@test.com"})
}

func TestEnforcer(t *testing.T) {
	// This role manager dose not rely on Casbin policy. So we should not
	// specify grouping policy ("g" policy rules) in the .csv file.
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		t.Errorf("NewEnforcer() failed: %s", err.Error())
	}

	// Use our role manager.
	rm := NewRoleManager("dev-000000", "your_api_token", false)
	e.SetRoleManager(rm)

	// If our role manager relies on Casbin policy (like reading "g"
	// policy rules), then we have to set the role manager before loading
	// policy.
	//
	// Otherwise, we can set the role manager at any time, because role
	// manager has nothing to do with the adapter.
	e.LoadPolicy()

	// Current role inheritance tree:
	//           Everyone     Admin
	//         /          \  /
	// alice@test.com    bob@test.com

	// Note: you need to set this role inheritance in your Okta Admin portal
	// before running this test.

	testEnforce(t, e, "alice@test.com", "data1", "read", true)
	testEnforce(t, e, "alice@test.com", "data1", "write", false)
	testEnforce(t, e, "alice@test.com", "data2", "read", false)
	testEnforce(t, e, "alice@test.com", "data2", "write", true)
	testEnforce(t, e, "bob@test.com", "data1", "read", true)
	testEnforce(t, e, "bob@test.com", "data1", "write", false)
	testEnforce(t, e, "bob@test.com", "data2", "read", true)
	testEnforce(t, e, "bob@test.com", "data2", "write", true)
}

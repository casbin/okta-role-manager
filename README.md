Okta Role Manager [![Coverage Status](https://coveralls.io/repos/github/casbin/okta-role-manager/badge.svg?branch=master)](https://coveralls.io/github/casbin/okta-role-manager?branch=master) [![Godoc](https://godoc.org/github.com/casbin/okta-role-manager?status.svg)](https://godoc.org/github.com/casbin/okta-role-manager)
====

Okta Role Manager is the [Okta](https://www.okta.com/) role manager for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load role hierarchy (user-role mapping) from Okta or save role hierarchy to it (NOT Implemented).

## Installation

    go get github.com/casbin/okta-role-manager

## Simple Example

```go
package main

import (
	"github.com/casbin/casbin"
	"github.com/casbin/okta-role-manager"
)

func main() {
	// This role manager dose not rely on Casbin policy. So we should not
	// specify grouping policy ("g" policy rules) in the .csv file.
	e := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	// Use our role manager.
	// orgName is your organization name.
	// apiToken is the token you created in the Admin portal.
	// For example, if your domain name is like: dev-123456.oktapreview.com,
	// then your orgName is dev-123456, isProductionOrPreview is false.
	// If your domain name is like: company_name.okta.com, then your orgName
	// is company_name, isProductionOrPreview is true.
	rm := oktarolemanager.NewRoleManager("dev-000000", "your_api_token", false)
	e.SetRoleManager(rm)

	// If our role manager relies on Casbin policy (like reading "g"
	// policy rules), then we have to set the role manager before loading
	// policy.
	//
	// Otherwise, we can set the role manager at any time, because role
	// manager has nothing to do with the adapter.
	e.LoadPolicy()
	
	// Check the permission.
	// Casbin's subject (user) name uses the Okta user's login field (aka Email address).
	// Casbin's role name uses the Okta group's name field (like "Admin", "Everyone").
	e.Enforce("alice@test.com", "data1", "read")
}
```

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.

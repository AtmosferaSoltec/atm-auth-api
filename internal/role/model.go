// Package role exposes the roles each system defines. They are declared in code (package catalog), so this package
// only lists them: the console shows them and gives them to people through the access feature.
package role

import "time"

// Role is a role a system defines. The platform does not know what it allows: that is up to the system.
type Role struct {
	ID          string
	SystemID    string
	Name        string
	Description string
	// Active is false for a role the catalog retired: it keeps its accesses but cannot be given to anyone.
	Active bool
	// Users is how many people have this role today.
	Users     int
	CreatedAt time.Time
}

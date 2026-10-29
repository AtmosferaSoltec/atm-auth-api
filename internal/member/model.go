package member

// Scope is what a tenant owner may act on: one tenant inside one system.
// It always comes from the owner's current access, never from the request.
type Scope struct {
	ManagerID  string
	SystemID   string
	SystemCode string
	TenantID   string
}

// Member is a user with access to the scope's system inside the scope's tenant.
type Member struct {
	UserID             string
	DNI                string
	FullName           string
	Role               string
	ManageUsers        bool
	Status             string
	MustChangePassword bool
}

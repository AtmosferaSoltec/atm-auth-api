// Package catalog holds the systems of the platform and the roles each one defines. They live in code: the console
// only shows them and gives the roles to people. Sync copies them into the database every time the service starts.
package catalog

// Role is a role a system defines. The platform does not know what it allows: that is up to the system.
type Role struct {
	Name        string
	Description string
}

// System is a system of the platform with its fixed roles.
type System struct {
	Code string
	Name string
	// RequiresRUC says whether the system can only be enabled for companies that have a RUC.
	RequiresRUC bool
	Roles       []Role
}

// Systems is the one place where systems and roles are declared. To add a role or a system, add a line here and deploy:
// Sync creates it on start. Secrets are never declared here; they are generated per environment from the console.
var Systems = []System{
	{
		Code: "pulso", Name: "Pulso", RequiresRUC: false,
		Roles: []Role{
			{Name: "admin", Description: "Manages the team, the gym settings and everything in the company."},
			{Name: "receptionist", Description: "Registers members, payments and entries in the branches assigned to them."},
			// The "member" role (a gym member using the app) is not active yet. To enable it, add:
			// {Name: "member", Description: "Uses the app as a member of the gym."},
		},
	},
	{
		Code: "lavendimia", Name: "La Vendimia", RequiresRUC: true,
		Roles: []Role{
			{Name: "admin", Description: "Manages the company, the catalog, the team and every sale."},
			{Name: "cashier", Description: "Registers sales and dispatches."},
		},
	},
	{
		// Dental clinics. Roles come from the Nova web prototype (src/types/app.types.ts); "owner" is the manage_users flag
		// of an access and "superadmin" is reserved, so neither is a catalog role.
		Code: "nova", Name: "Nova", RequiresRUC: true,
		Roles: []Role{
			{Name: "admin", Description: "Manages the clinic, the team and everything in the company."},
			{Name: "receptionist", Description: "Manages appointments and basic patient information."},
			{Name: "cashier", Description: "Registers estimates and payments."},
			{Name: "dentist", Description: "Sees appointments, patients, the dental chart and estimates."},
		},
	},
	{
		// Personal finance. No sibling repo defines roles, so only admin is declared.
		Code: "orbita", Name: "Orbita", RequiresRUC: false,
		Roles: []Role{
			{Name: "admin", Description: "Full access to the account."},
		},
	},
	{
		// Declared only: the Olympus production client does not use this service yet and no user is migrated by this entry.
		// Roles come from the rol table of olympuscourier-backend (S SuperAdmin is reserved and left out).
		Code: "olympuscourier", Name: "Olympus Courier", RequiresRUC: true,
		Roles: []Role{
			{Name: "admin", Description: "Manages the company, the team and every delivery."},
			{Name: "user", Description: "Requests and follows deliveries."},
			{Name: "delivery", Description: "Carries out deliveries."},
		},
	},
}

// Orphans is what the database holds that the catalog does not declare. Sync reports it, retires its roles and never deletes anything.
type Orphans struct {
	// Systems are codes of systems missing from the catalog.
	Systems []string
	// Roles are roles missing from the catalog, with how many people still have each one.
	Roles []OrphanRole
}

type OrphanRole struct {
	SystemCode string
	Name       string
	Users      int
}

func (o Orphans) Empty() bool { return len(o.Systems) == 0 && len(o.Roles) == 0 }

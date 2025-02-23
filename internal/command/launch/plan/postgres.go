package plan

import (
	"github.com/superfly/flyctl/api"
)

type PostgresPlan struct {
	FlyPostgres *FlyPostgresPlan `json:"fly_postgres"`
}

func (p *PostgresPlan) Provider() any {
	if p == nil {
		return nil
	}
	if p.FlyPostgres != nil {
		return p.FlyPostgres
	}
	return nil
}

func DefaultPostgres(plan *LaunchPlan) PostgresPlan {
	return PostgresPlan{
		FlyPostgres: &FlyPostgresPlan{
			// NOTE: Until Legacy Launch is removed, we have to maintain
			//       "%app_name%-db" as the app name for the database.
			//       (legacy launch does not have a single source-of-truth name for the db,
			//        so it constructs the name on-the-spot each time it needs it)
			AppName:    plan.AppName + "-db",
			VmSize:     "shared-cpu-1x",
			VmRam:      1024,
			Nodes:      1,
			DiskSizeGB: 10,
		},
	}
}

type FlyPostgresPlan struct {
	AppName    string `json:"app_name"`
	VmSize     string `json:"vm_size"`
	VmRam      int    `json:"vm_ram"`
	Nodes      int    `json:"nodes"`
	DiskSizeGB int    `json:"disk_size_gb"`
	AutoStop   bool   `json:"auto_stop"`
}

func (p *FlyPostgresPlan) Guest() *api.MachineGuest {
	guest := api.MachineGuest{}
	guest.SetSize(p.VmSize)
	if p.VmRam != 0 {
		guest.MemoryMB = p.VmRam
	}
	return &guest
}

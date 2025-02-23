package machine

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/superfly/flyctl/api"
	"github.com/superfly/flyctl/client"
	"github.com/superfly/flyctl/flaps"
	"github.com/superfly/flyctl/internal/appconfig"
	"github.com/superfly/flyctl/internal/command"
	"github.com/superfly/flyctl/internal/flag"
	"github.com/superfly/flyctl/iostreams"
)

func newDestroy() *cobra.Command {
	const (
		short = "Destroy Fly machines"
		long  = `Destroy one or more Fly machines.
This command requires a machine to be in a stopped state unless the force flag is used.
`
		usage = "destroy [flags] ID ID ..."
	)

	cmd := command.New(usage, short, long, runMachineDestroy,
		command.RequireSession,
		command.LoadAppNameIfPresent,
	)

	cmd.Aliases = []string{"remove", "rm"}

	flag.Add(
		cmd,
		flag.App(),
		flag.AppConfig(),
		selectFlag,
		flag.Bool{
			Name:        "force",
			Shorthand:   "f",
			Description: "force kill machine regardless of current state",
		},
	)

	cmd.Args = cobra.ArbitraryArgs

	return cmd
}

func runMachineDestroy(ctx context.Context) (err error) {
	if len(flag.Args(ctx)) == 0 {
		machine, ctx, err := selectOneMachine(ctx, nil, "", false)
		if err != nil {
			return err
		}
		err = singleDestroyRun(ctx, machine)
		if err != nil {
			return err
		}
	} else {
		machines, ctx, err := selectManyMachines(ctx, flag.Args(ctx))
		if err != nil {
			return err
		}

		for _, machine := range machines {
			err = singleDestroyRun(ctx, machine)
			if err != nil {
				return err
			}
		}

	}

	return nil
}

func singleDestroyRun(ctx context.Context, machine *api.Machine) error {
	var (
		out   = iostreams.FromContext(ctx).Out
		force = flag.GetBool(ctx, "force")
	)

	appName := appconfig.NameFromContext(ctx)

	// This is used for the deletion hook below.
	client := client.FromContext(ctx).API()
	app, err := client.GetAppCompact(ctx, appName)
	if err != nil {
		return fmt.Errorf("could not get app '%s': %w", appName, err)
	}

	err = Destroy(ctx, app, machine, force)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "%s has been destroyed\n", machine.ID)

	return nil
}

func Destroy(ctx context.Context, app *api.AppCompact, machine *api.Machine, force bool) error {
	var (
		out         = iostreams.FromContext(ctx).Out
		flapsClient = flaps.FromContext(ctx)

		input = api.RemoveMachineInput{
			ID:   machine.ID,
			Kill: force,
		}
	)

	switch machine.State {
	case "stopped":
		break
	case "destroyed":
		return fmt.Errorf("machine %s has already been destroyed", machine.ID)
	case "started":
		if !force {
			return fmt.Errorf("machine %s currently started, either stop first or use --force flag", machine.ID)
		}
	default:
		if !force {
			return fmt.Errorf("machine %s is in a %s state and cannot be destroyed since it is not stopped, either stop first or use --force flag", machine.ID, machine.State)
		}
	}
	fmt.Fprintf(out, "machine %s was found and is currently in %s state, attempting to destroy...\n", machine.ID, machine.State)

	err := flapsClient.Destroy(ctx, input, machine.LeaseNonce)
	if err != nil {
		if err := rewriteMachineNotFoundErrors(ctx, err, machine.ID); err != nil {
			return err
		}
		return fmt.Errorf("could not destroy machine %s: %w", machine.ID, err)
	}

	// Best effort post-deletion hook.
	runOnDeletionHook(ctx, app, machine)

	return nil
}

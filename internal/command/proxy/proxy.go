package proxy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/superfly/flyctl/agent"
	"github.com/superfly/flyctl/client"
	"github.com/superfly/flyctl/internal/appconfig"
	"github.com/superfly/flyctl/internal/command"
	"github.com/superfly/flyctl/internal/flag"
	"github.com/superfly/flyctl/internal/flag/flagnames"
	"github.com/superfly/flyctl/internal/prompt"
	"github.com/superfly/flyctl/proxy"
)

func New() *cobra.Command {
	var (
		long = strings.Trim(`Proxies connections to a Fly Machine through a WireGuard tunnel. By default,
connects to the first Machine address returned by an internal DNS query on the app.`, "\n")
		short = `Proxies connections to a Fly Machine.`
	)

	cmd := command.New("proxy <local:remote> [remote_host]", short, long, run,
		command.RequireSession, command.LoadAppNameIfPresent)

	cmd.Args = cobra.RangeArgs(1, 2)

	flag.Add(cmd,
		flag.App(),
		flag.AppConfig(),
		flag.Org(),
		flag.Bool{
			Name:        "select",
			Shorthand:   "s",
			Default:     false,
			Description: "Prompt to select from available Machines from the current application",
		},
		flag.Bool{
			Name:        "quiet",
			Shorthand:   "q",
			Description: "Don't print progress indicators for WireGuard",
		},
		flag.String{
			Name:        flagnames.BindAddr,
			Shorthand:   "b",
			Default:     "127.0.0.1",
			Description: "Local address to bind to",
		},
	)

	return cmd
}

func run(ctx context.Context) (err error) {
	client := client.FromContext(ctx).API()
	appName := appconfig.NameFromContext(ctx)

	orgSlug := flag.GetOrg(ctx)

	args := flag.Args(ctx)
	promptInstance := flag.GetBool(ctx, "select")

	if promptInstance && appName == "" {
		return errors.New("--app required when --select flag provided")
	}

	if orgSlug != "" {
		_, err := client.GetOrganizationBySlug(ctx, orgSlug)
		if err != nil {
			return err
		}
	}

	if appName == "" && orgSlug == "" {
		org, err := prompt.Org(ctx)
		if err != nil {
			return err
		}
		orgSlug = org.Slug
	}

	// var app *api.App
	if appName != "" {
		app, err := client.GetAppBasic(ctx, appName)
		if err != nil {
			return err
		}
		orgSlug = app.Organization.Slug
	}

	agentclient, err := agent.Establish(ctx, client)
	if err != nil {
		return err
	}

	// do this explicitly so we can get the DNS server address
	_, err = agentclient.Establish(ctx, orgSlug)
	if err != nil {
		return err
	}

	dialer, err := agentclient.ConnectToTunnel(ctx, orgSlug, flag.GetBool(ctx, "quiet"))
	if err != nil {
		return err
	}

	ports := strings.Split(args[0], ":")

	params := &proxy.ConnectParams{
		BindAddr:         flag.GetBindAddr(ctx),
		Ports:            ports,
		AppName:          appName,
		OrganizationSlug: orgSlug,
		Dialer:           dialer,
		PromptInstance:   promptInstance,
	}

	if len(args) > 1 {
		params.RemoteHost = args[1]
	} else {
		params.RemoteHost = fmt.Sprintf("%s.internal", appName)
	}

	return proxy.Connect(ctx, params)
}

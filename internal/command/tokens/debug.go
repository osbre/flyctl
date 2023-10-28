package tokens

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/superfly/flyctl/client"
	"github.com/superfly/flyctl/internal/command"
	"github.com/superfly/flyctl/internal/flag"
	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/flyio"
	"github.com/superfly/macaroon/resset"
)

func newDebug() *cobra.Command {
	const (
		short = "Debug Fly.io API tokens"
		long  = `Decode and print a Fly.io API token. The token to be
				debugged may either be passed in the -t argument or in FLY_API_TOKEN.
				See https://github.com/superfly/macaroon for details Fly.io macaroon
				tokens.`
		usage = "debug"
	)

	cmd := command.New(usage, short, long, runDebug)

	flag.Add(cmd,
		flag.String{
			Name:        "file",
			Shorthand:   "f",
			Description: "Filename to read caveats from. Defaults to stdin",
		},
	)

	return cmd
}

type mappings struct {
	orgs, apps map[int64]string
}

func retrieveMappings(ctx context.Context) (ret mappings, err error) {
	ret.orgs = map[int64]string{}
	ret.apps = map[int64]string{}

	client := client.FromContext(ctx)
	apps, err := client.API().GetApps(ctx, nil)
	if err != nil {
		return ret, err
	}

	for _, app := range apps {
		oid, _ /* never happening */ := strconv.ParseInt(app.Organization.InternalNumericID, 10, 64)

		ret.apps[app.InternalNumericID] = app.Name
		ret.orgs[oid] = app.Organization.Slug
	}

	return
}

func runDebug(ctx context.Context) error {
	toks, err := getTokens(ctx)
	if err != nil {
		return err
	}

	macs := make([]*macaroon.Macaroon, 0, len(toks))

	for i, tok := range toks {
		m, err := macaroon.Decode(tok)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to decode token at position %d: %s\n", i, err)
			continue
		}
		macs = append(macs, m)
	}

	maps, err := retrieveMappings(ctx)
	if err != nil {
		return err
	}

	for _, mac := range macs {
		printMacaroon(ctx, maps, mac)
	}

	if !flag.GetBool(ctx, "verbose") {
		return nil
	}

	// encode to buffer to avoid failing halfway through
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(macs); err != nil {
		return fmt.Errorf("unable to encode tokens: %w", err)
	}
	fmt.Println(buf.String())

	return nil
}

func printActions(ctx context.Context, act resset.Action) string {
	bits := []resset.Action{resset.ActionRead, resset.ActionWrite, resset.ActionCreate, resset.ActionDelete, resset.ActionControl}
	bitmap := map[resset.Action]string{
		resset.ActionRead:    "read",
		resset.ActionWrite:   "write",
		resset.ActionCreate:  "create",
		resset.ActionDelete:  "delete",
		resset.ActionControl: "control",
	}

	var everything resset.Action
	for _, b := range bits {
		everything |= b
	}

	if act&everything == everything {
		return "everything"
	}

	if act == resset.ActionRead {
		return "read-only"
	}

	actions := []string{}

	for _, b := range bits {
		if act&b == b {
			actions = append(actions, bitmap[b])
		}
	}

	if len(actions) == 1 {
		return actions[0]
	}

	return strings.Join(actions, ", ")
}

func printMacaroon(ctx context.Context, maps mappings, m *macaroon.Macaroon) error {
	m.Add(&flyio.Organization{ID: 9709, Mask: resset.ActionRead})
	m.Add(&flyio.Organization{ID: 9709, Mask: (resset.ActionRead | resset.ActionWrite)})
	m.Add(&flyio.Organization{ID: 9709, Mask: (resset.ActionWrite)})
	m.Add(&flyio.Apps{
		Apps: resset.ResourceSet[uint64]{
			9091:    resset.ActionRead,
			2004659: (resset.ActionRead | resset.ActionWrite),
			5392:    resset.ActionWrite,
		},
	})

	caveats := m.UnsafeCaveats.Caveats

	lookup := func(x uint64, mp map[int64]string) string {
		if v, ok := mp[int64(x)]; ok {
			return v
		}
		return fmt.Sprintf("%d", x)
	}

	kid := m.Nonce.KID
	if len(kid) > 6 {
		kid = kid[len(kid)-6:]
	}

	fmt.Printf("Token ...%x (from %s)\n", kid, m.Location)
	fmt.Printf("Caveats in this token:\n")

	depth := 0

	dep := func(f func()) {
		depth += 1
		f()
		depth -= 1
	}

	dprint := func(format string, args ...interface{}) {
		tabs := ""

		for i := 0; i < depth; i++ {
			tabs += "\t"
		}

		fmt.Printf(tabs+format+"\n", args...)
	}

	for _, ocav := range caveats {
		dep(func() {
			switch cav := ocav.(type) {
			case *flyio.Organization:
				dprint("* Exclusively for organization '%s'", lookup(cav.ID, maps.orgs))
				dep(func() {
					dprint("Allowed actions: %s", printActions(ctx, cav.Mask))
				})
			case *flyio.Apps:
				dprint("* Exclusive for the following apps:")
				for appid, axs := range cav.Apps {
					dep(func() {
						dprint("For app '%s', allowed actions: %s", lookup(appid, maps.apps), printActions(ctx, axs))
					})
				}
			case *macaroon.Caveat3P:
				switch cav.Location {
				case flyio.LocationAuthentication:
					dprint("* Requires authentication to Fly.io")
				}
			default:
				dprint("cav: %T %+v", cav, cav)
			}
		})
	}

	return nil
}

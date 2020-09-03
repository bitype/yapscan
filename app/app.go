package app

import (
	"encoding/hex"
	"fmt"
	"fraunhofer/fkie/yapscan"
	"fraunhofer/fkie/yapscan/procIO"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"

	"github.com/sirupsen/logrus"
	"github.com/targodan/go-errors"
	"github.com/urfave/cli/v2"
)

func initAppAction(c *cli.Context) error {
	lvl, err := logrus.ParseLevel(c.String("log-level"))
	if err != nil {
		return err
	}
	logrus.SetLevel(lvl)
	return nil
}

func listProcesses(c *cli.Context) error {
	err := initAppAction(c)
	if err != nil {
		return err
	}

	return errors.New("not implemented")
}

func filterFromArgs(c *cli.Context) (yapscan.MemorySegmentFilter, error) {
	var err error
	i := 0

	filters := make([]yapscan.MemorySegmentFilter, 8)

	filters[i], err = BuildFilterPermissions(c.String("filter-permissions"))
	if err != nil {
		return nil, errors.Errorf("invalid flag \"--filter-permissions\", reason: %w", err)
	}
	i += 1
	filters[i], err = BuildFilterPermissionsExact(c.StringSlice("filter-permissions-exact"))
	if err != nil {
		return nil, errors.Errorf("invalid flag \"--filter-permissions-exact\", reason: %w", err)
	}
	i += 1
	filters[i], err = BuildFilterType(c.StringSlice("filter-type"))
	if err != nil {
		return nil, errors.Errorf("invalid flag \"--filter-type\", reason: %w", err)
	}
	i += 1
	filters[i], err = BuildFilterState(c.StringSlice("filter-state"))
	if err != nil {
		return nil, errors.Errorf("invalid flag \"--filter-state\", reason: %w", err)
	}
	i += 1
	filters[i], err = BuildFilterSizeMax(c.String("filter-size-max"))
	if err != nil {
		return nil, errors.Errorf("invalid flag \"--filter-size-max\", reason: %w", err)
	}
	i += 1
	filters[i], err = BuildFilterSizeMin(c.String("filter-size-min"))
	if err != nil {
		return nil, errors.Errorf("invalid flag \"--filter-size-min\", reason: %w", err)
	}
	i += 1

	return yapscan.NewAndFilter(filters...), nil
}

func listMemory(c *cli.Context) error {
	err := initAppAction(c)
	if err != nil {
		return err
	}

	if c.NArg() != 1 {
		return errors.Newf("expected exactly one argument, got %d", c.NArg())
	}
	pid_, err := strconv.ParseUint(c.Args().Get(0), 10, 64)
	if err != nil {
		return errors.Newf("\"%s\" is not a pid", c.Args().Get(0))
	}
	pid := int(pid_)

	f, err := filterFromArgs(c)
	if err != nil {
		return err
	}

	proc, err := procIO.OpenProcess(pid)
	if err != nil {
		return errors.Newf("could not open process with pid %d, reason: %w", pid, err)
	}

	segments, err := proc.MemorySegments()
	if err != nil {
		return errors.Newf("could not enumerate memory segments of process %d, reason: %w", pid, err)
	}
	for _, seg := range segments {
		fRes := f.Filter(seg)
		if !fRes.Result {
			continue
		}

		format := "%19s %8s %3s %7s %7s %s\n"

		fmt.Printf(format, procIO.FormatMemorySegmentAddress(seg), humanize.Bytes(seg.Size), seg.CurrentPermissions, seg.Type, seg.State, seg.FilePath)

		if c.Bool("list-subdivided") {
			for i, sseg := range seg.SubSegments {
				addr := procIO.FormatMemorySegmentAddress(sseg)
				if i+1 < len(seg.SubSegments) {
					addr = "├" + addr
				} else {
					addr = "└" + addr
				}

				fmt.Printf(format, addr, humanize.Bytes(sseg.Size), sseg.CurrentPermissions, sseg.Type, sseg.State, sseg.FilePath)
			}
		}
	}

	return nil
}

func dumpMemory(c *cli.Context) error {
	err := initAppAction(c)
	if err != nil {
		return err
	}

	var dumper io.WriteCloser
	if c.Bool("raw") {
		dumper = os.Stdout
	} else {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	if c.NArg() != 2 {
		return errors.Newf("expected exactly two arguments, got %d", c.NArg())
	}
	pid_, err := strconv.ParseUint(c.Args().Get(0), 10, 64)
	if err != nil {
		return errors.Newf("\"%s\" is not a pid", c.Args().Get(0))
	}
	pid := int(pid_)

	addrS := c.Args().Get(1)
	if strings.Index(addrS, "0x") == 0 {
		addrS = addrS[2:]
	}
	addr, err := strconv.ParseUint(addrS, 16, 64)
	if err != nil {
		return errors.Newf("\"%s\" is not an address", c.Args().Get(1))
	}

	proc, err := procIO.OpenProcess(pid)
	if err != nil {
		return errors.Newf("could not open process %d, reason: %w", pid, err)
	}

	segments, err := proc.MemorySegments()
	if err != nil {
		return errors.Newf("could not retrieve memory segments of process %d, reason: %w", pid, err)
	}
	readContiguous := c.Int("contiguous")
	found := false
	for i, seg := range segments {
		if seg.BaseAddress == addr {
			found = true
		}
		if found {
			rdr, err := procIO.NewMemoryReader(proc, seg)
			if err != nil {
				return errors.Newf("could not read memory of process %d at address 0x%016X, reason %w", pid, seg.BaseAddress, err)
			}
			_, err = io.Copy(dumper, rdr)
			if err != nil {
				return errors.Newf("could not read memory of process %d at address 0x%016X, reason %w", pid, seg.BaseAddress, err)
			}

			if readContiguous == 0 || (i+1 < len(segments) && segments[i+1].BaseAddress != seg.BaseAddress+seg.Size) {
				// Next segment is not contiguous
				break
			}
		}
	}
	if !found {
		errors.Newf("process %d has no memory segment starting with address 0x%016X", pid, addr)
	}
	return nil
}

func RunApp(args []string) {
	segmentFilterFlags := []cli.Flag{
		&cli.StringFlag{
			Name:    "filter-permissions",
			Aliases: []string{"f-perm"},
			Usage:   "only consider segments with the given permissions or more, examples: \"rw\" includes segments with rw, rc and rwx",
		},
		&cli.StringSliceFlag{
			Name:    "filter-permissions-exact",
			Aliases: []string{"f-perm-e"},
			Usage:   "comma separated list of permissions to be considered, supported permissions: r, rw, rc, rwx, rcx",
		},
		&cli.StringSliceFlag{
			Name:    "filter-type",
			Aliases: []string{"f-type"},
			Usage:   "comma separated list of considered types, supported types: image, mapped, private",
		},
		&cli.StringSliceFlag{
			Name:    "filter-state",
			Aliases: []string{"f-state"},
			Usage:   "comma separated list of considered states, supported states: free, commit, reserve",
			Value:   cli.NewStringSlice("commit", "reserve"),
		},
		&cli.StringFlag{
			Name:    "filter-size-max",
			Aliases: []string{"f-size-max"},
			Usage:   "maximum size of memory segments to be considered, can be absolute (e.g. \"1.5GB\"), percentage of total RAM (e.g. \"10%T\") or percentage of free RAM (e.g. \"10%F\")",
			Value:   "10%F",
		},
		&cli.StringFlag{
			Name:    "filter-size-min",
			Aliases: []string{"f-size-min"},
			Usage:   "minimum size of memory segments to be considered",
		},
	}

	app := &cli.App{
		Name:        "yapscan",
		HelpName:    "yapscan",
		Description: "A yara based scanner for files and process memory with some extras.",
		Version:     "0.1.0",
		Authors: []*cli.Author{
			&cli.Author{
				Name:  "Luca Corbatto",
				Email: "luca.corbatto@fkie.fraunhofer.de",
			},
		},
		EnableBashCompletion: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{"l"},
				Usage:   "one of [trace, debug, info, warn, error, fatal]",
				Value:   "info",
			},
		},
		Commands: []*cli.Command{
			&cli.Command{
				Name:    "list-processes",
				Aliases: []string{"ps", "lsproc"},
				Usage:   "lists all running processes",
				Action:  listProcesses,
			},
			&cli.Command{
				Name:      "list-process-memory",
				Aliases:   []string{"lsmem"},
				Usage:     "lists all memory segments of a process",
				ArgsUsage: "<pid>",
				Flags: append([]cli.Flag{
					&cli.BoolFlag{
						Name:  "list-free",
						Usage: "also list free memory segments",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "list-subdivided",
						Usage: "list segment subdivisions as they are now, as opposed to segments as they were allocated once",
					},
				}, segmentFilterFlags...),
				Action: listMemory,
			},
			&cli.Command{
				Name:      "dump",
				Usage:     "dumps memory of a process",
				Action:    dumpMemory,
				ArgsUsage: "<pid> <address_of_section>",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:    "contiguous",
						Aliases: []string{"c"},
						Usage:   "also dump the following <value> contiguous sections, -1 for all contiguous sections",
					},
					&cli.BoolFlag{
						Name:    "raw",
						Aliases: []string{"r"},
						Usage:   "dump the raw memory as opposed to a hex view of the memory",
						Value:   false,
					},
				},
			},
		},
	}

	err := app.Run(args)
	if err != nil {
		logrus.Fatal(err)
	}
}
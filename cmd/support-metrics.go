// Copyright (c) 2015-2022 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"errors"
	"fmt"
	"io"

	"github.com/minio/cli"
	json "github.com/minio/colorjson"
	"github.com/minio/madmin-go"
)

var supportMetricsCmd = cli.Command{
	Name:         "metrics",
	Usage:        "upload health data for diagnostics",
	OnUsageError: onUsageError,
	Action:       mainSupportMetrics,
	Before:       setGlobalsFromContext,
	Flags:        append(subnetCommonFlags, globalFlags...),
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} TARGET

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}
EXAMPLES:
  1. Upload MinIO support metrics for 'play' (https://play.min.io by default) to SUBNET
     {{.Prompt}} {{.HelpName}} play

  2. Generate MinIO diagnostics report for alias 'play' (https://play.min.io by default) save and upload to SUBNET manually
     {{.Prompt}} {{.HelpName}} play --airgap
`,
}

func mainSupportMetrics(ctx *cli.Context) error {
	// Get the alias parameter from cli
	aliasedURL := ctx.Args().Get(0)
	// alias, _ := url2Alias(aliasedURL)

	// Create a new MinIO Admin Client
	client := getClient(aliasedURL)
	d, ver, e := client.SupportMetrics(globalContext, client)
	if e != nil {
		fmt.Println("Returning with error:", e.Error())
		return e
	}

	m := madmin.SupportMetrics{}
	switch ver {
	case madmin.SupportMetricsVersion:
		if e = json.Unmarshal(d, &m); e != nil {
			if errors.Is(e, io.EOF) {
				e = nil
			} else {
				return e
			}
		}
		j, e := json.Marshal(m)
		if e == nil {
			fmt.Println(string(j))
		} else {
			fmt.Println(e.Error())
		}
	default:
		fmt.Println("Unknown version", ver)
		return errors.New("Unknown error")
	}

	return nil
}

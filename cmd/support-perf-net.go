// Copyright (c) 2022 MinIO, Inc.
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
	"context"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/minio/cli"
	"github.com/minio/madmin-go"
	"github.com/minio/mc/pkg/probe"
)

func mainAdminSpeedTestNetperf(ctx *cli.Context, aliasedURL string) error {
	return execSpeedTestNetperf(ctx, aliasedURL, nil)
}

func execSpeedTestNetperf(ctx *cli.Context, aliasedURL string, outChan chan SpeedTestResult) error {
	client, perr := newAdminClient(aliasedURL)
	if perr != nil {
		fatalIf(perr.Trace(aliasedURL), "Unable to initialize admin client.")
		return nil
	}

	ctxt, cancel := context.WithCancel(globalContext)
	defer cancel()

	duration, e := time.ParseDuration(ctx.String("duration"))
	if e != nil {
		fatalIf(probe.NewError(e), "Unable to parse duration")
		return nil
	}
	if duration <= 0 {
		fatalIf(errInvalidArgument(), "duration cannot be 0 or negative")
		return nil
	}

	resultCh := make(chan madmin.NetperfResult)
	errorCh := make(chan error)
	go func() {
		defer close(resultCh)
		defer close(errorCh)

		result, err := client.Netperf(ctxt, duration)
		if err != nil {
			errorCh <- err
		}
		resultCh <- result
	}()

	if globalJSON {
		select {
		case err := <-errorCh:
			printMsg(SpeedTestResult{
				Type:  netSpeedTest,
				Err:   err.Error(),
				Final: true,
			})
		case result := <-resultCh:
			printMsg(SpeedTestResult{
				Type:      netSpeedTest,
				NetResult: &result,
				Final:     true,
			})
		}
		return nil
	}

	done := make(chan struct{})

	p := tea.NewProgram(initSpeedTestUI())
	go func() {
		if e := p.Start(); e != nil {
			os.Exit(1)
		}
		close(done)
	}()

	go func() {
		for {
			select {
			case err := <-errorCh:
				p.Send(SpeedTestResult{
					Type:  netSpeedTest,
					Err:   err.Error(),
					Final: true,
				})
				return
			case result := <-resultCh:
				r := SpeedTestResult{
					Type:      netSpeedTest,
					NetResult: &result,
					Final:     true,
				}
				p.Send(r)
				if outChan != nil {
					outChan <- r
				}
				return
			default:
				p.Send(SpeedTestResult{
					Type:      netSpeedTest,
					NetResult: &madmin.NetperfResult{},
				})
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	<-done

	return nil
}

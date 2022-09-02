// Copyright (c) 2015-2021 MinIO, Inc.
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
	"archive/zip"
	gojson "encoding/json"
	"fmt"
	"os"
	"path/filepath"

	humanize "github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/minio/cli"
	json "github.com/minio/colorjson"
	"github.com/minio/madmin-go"
	"github.com/minio/mc/pkg/probe"
	"github.com/minio/pkg/console"
)

var supportPerfFlags = append([]cli.Flag{
	cli.StringFlag{
		Name:  "duration",
		Usage: "duration the entire perf tests are run",
		Value: "10s",
	},
	cli.BoolFlag{
		Name:  "verbose, v",
		Usage: "display per-server stats",
	},
	cli.StringFlag{
		Name:   "size",
		Usage:  "size of the object used for uploads/downloads",
		Value:  "64MiB",
		Hidden: true,
	},
	cli.IntFlag{
		Name:   "concurrent",
		Usage:  "number of concurrent requests per server",
		Value:  32,
		Hidden: true,
	},
	cli.StringFlag{
		Name:   "bucket",
		Usage:  "provide a custom bucket name to use (NOTE: bucket must be created prior)",
		Hidden: true, // Hidden for now.
	},
	// Drive test specific flags.
	cli.StringFlag{
		Name:   "filesize",
		Usage:  "total amount of data read/written to each drive",
		Value:  "1GiB",
		Hidden: true,
	},
	cli.StringFlag{
		Name:   "blocksize",
		Usage:  "read/write block size",
		Value:  "4MiB",
		Hidden: true,
	},
	cli.BoolFlag{
		Name:   "serial",
		Usage:  "run tests on drive(s) one-by-one",
		Hidden: true,
	},
}, subnetCommonFlags...)

var supportPerfCmd = cli.Command{
	Name:            "perf",
	Usage:           "analyze object, network and drive performance",
	Action:          mainSupportPerf,
	OnUsageError:    onUsageError,
	Before:          setGlobalsFromContext,
	Flags:           append(supportPerfFlags, globalFlags...),
	HideHelpCommand: true,
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} [COMMAND] [FLAGS] TARGET

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}

EXAMPLES:
  1. Run object storage, network, and drive performance tests on 'myminio' cluster:
     {{.Prompt}} {{.HelpName}} myminio/
`,
}

func objectTestVerboseResult(result *madmin.SpeedTestResult) (msg string) {
	msg += "PUT:\n"
	for _, node := range result.PUTStats.Servers {
		msg += fmt.Sprintf("   * %s: %s/s %s objs/s", node.Endpoint, humanize.IBytes(node.ThroughputPerSec), humanize.Comma(int64(node.ObjectsPerSec)))
		if node.Err != "" {
			msg += " Err: " + node.Err
		}
		msg += "\n"
	}

	msg += "GET:\n"
	for _, node := range result.GETStats.Servers {
		msg += fmt.Sprintf("   * %s: %s/s %s objs/s", node.Endpoint, humanize.IBytes(node.ThroughputPerSec), humanize.Comma(int64(node.ObjectsPerSec)))
		if node.Err != "" {
			msg += " Err: " + node.Err
		}
		msg += "\n"
	}

	return msg
}

func objectTestShortResult(result *madmin.SpeedTestResult) (msg string) {
	msg += fmt.Sprintf("MinIO %s, %d servers, %d drives, %s objects, %d threads",
		result.Version, result.Servers, result.Disks,
		humanize.IBytes(uint64(result.Size)), result.Concurrent)

	return msg
}

func (s SpeedTestResult) String() string {
	return ""
}

func (s SpeedTestResult) JSON() string {
	JSONBytes, e := json.MarshalIndent(s, "", "    ")
	fatalIf(probe.NewError(e), "Unable to marshal into JSON.")
	return string(JSONBytes)
}

var globalPerfTestVerbose bool

func mainSupportPerf(ctx *cli.Context) error {
	args := ctx.Args()

	// the alias parameter from cli
	aliasedURL := ""
	perfType := ""
	switch len(args) {
	case 1:
		// cannot use alias by the name 'drive' or 'net'
		if args[0] == "drive" || args[0] == "net" || args[0] == "object" {
			cli.ShowCommandHelpAndExit(ctx, "perf", 1)
		}
		aliasedURL = args[0]

	case 2:
		aliasedURL = args[1]
		perfType = args[1]
	default:
		cli.ShowCommandHelpAndExit(ctx, "perf", 1) // last argument is exit code
	}

	// Main execution
	execSupportPerf(ctx, aliasedURL, perfType)

	return nil
}

func execSupportPerf(ctx *cli.Context, aliasedURL string, perfType string) {
	alias, apiKey := initSubnetConnectivity(ctx, aliasedURL)

	var reqURL string
	var headers map[string]string

	// if `--airgap` is provided do not try to upload to SUBNET.
	if !globalAirgapped {
		fatalIf(checkURLReachable(subnetBaseURL()).Trace(aliasedURL), "Unable to reach %s to upload MinIO profile file, please use --airgap to upload manually", subnetBaseURL())
		// Retrieve subnet credentials (login/license) beforehand as
		// it can take a long time to fetch the profile data
		uploadURL := subnetUploadURL("perf", profileFile)
		reqURL, headers = prepareSubnetUploadURL(uploadURL, alias, profileFile, apiKey)
	}

	finalResult := []SpeedTestResult{}
	resultCh := make(chan SpeedTestResult)
	defer close(resultCh)

	switch perfType {
	case "":
		finalResult = append(finalResult, triggerNetTest(ctx, aliasedURL, resultCh))
		finalResult = append(finalResult, triggerDriveTest(ctx, aliasedURL, resultCh))
		finalResult = append(finalResult, triggerObjectTest(ctx, aliasedURL, resultCh))
	case "drive":
		finalResult = append(finalResult, triggerDriveTest(ctx, aliasedURL, resultCh))
	case "object":
		finalResult = append(finalResult, triggerObjectTest(ctx, aliasedURL, resultCh))
	case "net":
		finalResult = append(finalResult, triggerNetTest(ctx, aliasedURL, resultCh))
	default:
		cli.ShowCommandHelpAndExit(ctx, "perf", 1) // last argument is exit code
	}

	resultFileName := fmt.Sprintf("%s-perf_%s.json", filepath.Clean(alias), UTCNow().Format("20060102150405"))
	regInfo := getClusterRegInfo(getAdminInfo(aliasedURL), alias)
	tmpFileName, e := zipPerfResult(finalResult, resultFileName, regInfo)
	fatalIf(probe.NewError(e), "Error creating gzip from perf results:")

	clr := color.New(color.FgGreen, color.Bold)
	if !globalAirgapped {
		// JSONBytes, _ := json.MarshalIndent(finalResult, "", "    ")
		// fmt.Println(string(JSONBytes))
		_, e := uploadFileToSubnet(alias, tmpFileName, reqURL, headers)
		fatalIf(probe.NewError(e), "Unable to upload perf results to SUBNET portal:")
		if len(apiKey) > 0 {
			setSubnetAPIKey(alias, apiKey)
		}
		clr.Println("uploaded successfully to SUBNET.")
	} else {
		filename := fmt.Sprintf("%s-perf_%s.gz", filepath.Clean(alias), UTCNow().Format("20060102150405"))
		fi, e := os.Stat(tmpFileName)
		fatalIf(probe.NewError(e), "Unable to upload perf results to SUBNET portal:")
		moveFile(tmpFileName, fi.Name())
		console.Infoln("MinIO performance report saved at", filename)
	}

}

func triggerDriveTest(ctx *cli.Context, aliasedURL string, resultCh chan SpeedTestResult) SpeedTestResult {
	go execSpeedTestDrive(ctx, aliasedURL, resultCh)
	return <-resultCh
}

func triggerObjectTest(ctx *cli.Context, aliasedURL string, resultCh chan SpeedTestResult) SpeedTestResult {
	go execSpeedTestObject(ctx, aliasedURL, resultCh)
	return <-resultCh
}

func triggerNetTest(ctx *cli.Context, aliasedURL string, resultCh chan SpeedTestResult) SpeedTestResult {
	go execSpeedTestNetperf(ctx, aliasedURL, resultCh)
	return <-resultCh
}

// compress MinIO performance output
func zipPerfResult(perfResult []SpeedTestResult, resultFilename string, regInfo ClusterRegistrationInfo) (string, error) {
	// Create profile zip file
	tmpArchive, e := os.CreateTemp("", "mc-perf-")

	if e != nil {
		return "", e
	}
	defer tmpArchive.Close()

	zipWriter := zip.NewWriter(tmpArchive)
	defer zipWriter.Close()

	perfResultWriter, e := zipWriter.Create(resultFilename)
	if e != nil {
		return "", e
	}

	enc := gojson.NewEncoder(perfResultWriter)
	if e = enc.Encode(perfResult); e != nil {
		return "", e
	}

	clusterInfoWriter, e := zipWriter.Create("cluster.info")
	if e != nil {
		return "", e
	}

	enc = gojson.NewEncoder(clusterInfoWriter)
	if e = enc.Encode(regInfo); e != nil {
		return "", e
	}

	return tmpArchive.Name(), nil
}

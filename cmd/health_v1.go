/*
 * MinIO Cloud Storage, (C) 2020 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package cmd

import (
	"encoding/json"

	"github.com/minio/mc/pkg/probe"
	"github.com/minio/minio-go/v7/pkg/set"
	"github.com/minio/minio/pkg/madmin"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
)

// HwServersV1 - hardware health Info
type HwServersV1 struct {
	Servers []HwServerV1 `json:"servers,omitempty"`
}

// HwServerV1 - server health Info
type HwServerV1 struct {
	Addr    string        `json:"addr"`
	CPUs    []HwCPUV1     `json:"cpus,omitempty"`
	MemInfo []HwMemV1     `json:"meminfos,omitempty"`
	Network []HwNetworkV1 `json:"network,omitempty"`
	Perf    HwPerfV1      `json:"perf,omitempty"`
}

// HwCPUV1 - CPU Info
type HwCPUV1 struct {
	CPUStat   []cpu.InfoStat  `json:"cpu,omitempty"`
	TimesStat []cpu.TimesStat `json:"time,omitempty"`
	Error     string          `json:"error,omitempty"`
}

// HwMemV1 - Includes host virtual and swap mem information
type HwMemV1 struct {
	SwapMem    *mem.SwapMemoryStat    `json:"swap,omitempty"`
	VirtualMem *mem.VirtualMemoryStat `json:"virtualmem,omitempty"`
	Error      string                 `json:"error,omitempty"`
}

// HwNetworkV1 - Network info
type HwNetworkV1 struct {
	Addr   string `json:"addr"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// HwPerfV1 - hardware performance
type HwPerfV1 struct {
	Net   HwNetPerfV1   `json:"net,omitempty"`
	Drive HwDrivePerfV1 `json:"drives,omitempty"`
}

// HwNetPerfV1 - Network performance info
type HwNetPerfV1 struct {
	Serial   []madmin.NetPerfInfo `json:"serial,omitempty"`
	Parallel []madmin.NetPerfInfo `json:"parallel,omitempty"`
}

// HwDrivePerfV1 - Network performance info
type HwDrivePerfV1 struct {
	Serial   []madmin.DrivePerfInfo `json:"serial,omitempty"`
	Parallel []madmin.DrivePerfInfo `json:"parallel,omitempty"`
	Error    string                 `json:"error,omitempty"`
}

// SwInfoV1 - software health Info
type SwInfoV1 struct {
	Minio  MinioHealthInfoV1           `json:"minio,omitempty"`
	OsInfo []madmin.ServerOsHealthInfo `json:"osinfos,omitempty"`
}

// MinioHealthInfoV1 - Health info of the MinIO cluster
type MinioHealthInfoV1 struct {
	Info     madmin.InfoMessage      `json:"info,omitempty"`
	Config   interface{}             `json:"config,omitempty"`
	ProcInfo []madmin.ServerProcInfo `json:"procinfos,omitempty"`
	Error    string                  `json:"error,omitempty"`
}

// ClusterHealthV1 - main struct of the health report
type ClusterHealthV1 struct {
	Status   string      `json:"status"`
	Error    string      `json:"error,omitempty"`
	Hardware HwServersV1 `json:"hardware,omitempty"`
	Software SwInfoV1    `json:"software,omitempty"`
}

func (ch ClusterHealthV1) String() string {
	return ch.JSON()
}

// JSON jsonifies service status message.
func (ch ClusterHealthV1) JSON() string {
	statusJSONBytes, e := json.MarshalIndent(ch, " ", "    ")
	fatalIf(probe.NewError(e), "Unable to marshal into JSON.")

	return string(statusJSONBytes)
}

func (ch ClusterHealthV1) getStatus() string {
	return ch.Status
}

func (ch ClusterHealthV1) setStatus(status string) {
	ch.Status = status
}

func (ch ClusterHealthV1) getError() string {
	return ch.Error
}

func (ch ClusterHealthV1) setError(error string) {
	ch.Error = error
}

func (ch ClusterHealthV1) mapHealthInfo(healthInfo madmin.HealthInfo, err error) ReportInfo {
	if err != nil {
		ch.Status = "Error"
		ch.Error = err.Error()
	} else {
		ch.Status = "Success"
	}

	hw := HwServersV1{Servers: []HwServerV1{}}

	serverAddrs := set.NewStringSet()

	// Map CPU info
	serverCPUs := map[string][]HwCPUV1{}
	for _, ci := range healthInfo.Sys.CPUInfo {
		cpus, ok := serverCPUs[ci.Addr]
		if !ok {
			cpus = []HwCPUV1{}
		}
		cpus = append(cpus, HwCPUV1{
			CPUStat:   ci.CPUStat,
			TimesStat: ci.TimeStat,
			Error:     ci.Error,
		})
		serverCPUs[ci.Addr] = cpus
	}

	// Map memory info
	serverMems := map[string][]HwMemV1{}
	for _, mi := range healthInfo.Sys.MemInfo {
		mems, ok := serverMems[mi.Addr]
		if !ok {
			mems = []HwMemV1{}
		}
		mems = append(mems, HwMemV1{
			SwapMem:    mi.SwapMem,
			VirtualMem: mi.VirtualMem,
			Error:      mi.Error,
		})
		serverMems[mi.Addr] = mems
	}

	// Map network info
	serverNetPerfSerial := map[string][]madmin.NetPerfInfo{}

	for _, serverPerf := range healthInfo.Perf.Net {
		serverNetPerfSerial[serverPerf.Addr] = serverPerf.Net
	}

	serverNetPerfParallel := map[string][]madmin.NetPerfInfo{}
	serverNetPerfParallel[healthInfo.Perf.NetParallel.Addr] = healthInfo.Perf.NetParallel.Net

	serverNetworks := map[string][]HwNetworkV1{}
	for _, srvr := range healthInfo.Minio.Info.Servers {
		for addr, status := range srvr.Network {
			nets, ok := serverNetworks[srvr.Endpoint]
			if !ok {
				nets = []HwNetworkV1{}
			}

			nets = append(nets, HwNetworkV1{
				Addr:   addr,
				Status: status,
			})
			serverNetworks[srvr.Endpoint] = nets
		}

	}

	serverDrivePerf := map[string]HwDrivePerfV1{}
	for _, drivePerf := range healthInfo.Perf.DriveInfo {
		dp := HwDrivePerfV1{
			Serial:   drivePerf.Serial,
			Parallel: drivePerf.Parallel,
			Error:    drivePerf.Error,
		}
		serverDrivePerf[drivePerf.Addr] = dp
	}

	for addr := range serverCPUs {
		serverAddrs.Add(addr)
	}

	for addr := range serverMems {
		serverAddrs.Add(addr)
	}

	for addr := range serverNetworks {
		serverAddrs.Add(addr)
	}

	for addr := range serverNetPerfSerial {
		serverAddrs.Add(addr)
	}

	serverAddrs.Add(healthInfo.Perf.NetParallel.Addr)

	for addr := range serverDrivePerf {
		serverAddrs.Add(addr)
	}

	// Merge all hw info into servers
	for addr := range serverAddrs {
		perf := HwPerfV1{
			Net: HwNetPerfV1{
				Serial:   serverNetPerfSerial[addr],
				Parallel: serverNetPerfParallel[addr],
			},
			Drive: serverDrivePerf[addr],
		}
		hw.Servers = append(hw.Servers, HwServerV1{
			Addr:    addr,
			CPUs:    serverCPUs[addr],
			MemInfo: serverMems[addr],
			Network: serverNetworks[addr],
			Perf:    perf,
		})
	}

	ch.Hardware = hw
	ch.Software = SwInfoV1{
		Minio: MinioHealthInfoV1{
			Info:     healthInfo.Minio.Info,
			Config:   healthInfo.Minio.Config,
			Error:    healthInfo.Minio.Error,
			ProcInfo: healthInfo.Sys.ProcInfo,
		},
		OsInfo: healthInfo.Sys.OsInfo,
	}
	return ch
}

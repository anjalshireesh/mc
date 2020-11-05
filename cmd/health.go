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

import "github.com/minio/minio/pkg/madmin"

// ReportInfo - interface to be implemented by health report schema struct
type ReportInfo interface {
	getStatus() string
	getError() string
	message
	mapHealthInfo(healthInfo madmin.HealthInfo, err error) ReportInfo
}

// HealthReportHeader - Header of the subnet health report
// expected to generate JSON output of the form
// {"subnet":{"health":{"version":"v1"}}}
type HealthReportHeader struct {
	Subnet Health `json:"subnet"`
}

// Health - intermediate struct for subnet health header
// Just used to achieve the JSON structure we want
type Health struct {
	Health SchemaVersion `json:"health"`
}

// SchemaVersion - version of the health report schema
type SchemaVersion struct {
	Version string `json:"version"`
}

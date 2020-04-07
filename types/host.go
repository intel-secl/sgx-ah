/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

//  Host struct is the database schema of a Hosts table
type Host struct {
	Id            string    `json:"host_id" gorm:"type:uuid;unique;primary_key;"`
	HostName      string    `json:"host_name"`
	ConnectionURL string    `json:"connection_url"`
	HardwareUUID  string    `json:"uuid" gorm:"type:uuid;unique"`
	CreatedTime   time.Time `json:"-"`
	UpdatedTime   time.Time `json:"-"`
	SGXSupported  bool      `json:"sgx_supported"`
	SGXEnabled    bool      `json:"sgx_enabled"`
	FLCEnabled    bool      `json:"flc_enabled"`
	EPCSize       string    `json:"epc_size"`
	TCBUpToDate   bool      `json:"tcb_upToDate"`
	Deleted       bool      `json:"-" gorm:"type:bool;not null;default:false"`
}

type Hosts []Host

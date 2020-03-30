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
	Id                 string     `json:"-" gorm:"type:uuid;unique;primary_key;"`
	HardwareUUID       string     `json:"-" gorm:"type:uuid;unique"`
	HostName           string     `json:"-"`
	ConnectionURL      string     `json:"-"`
	CreatedTime        time.Time  `json:"-"`
	UpdatedTime        time.Time  `json:"-"`
	SGXSupported       bool	      `json:"-"`
	SGXEnabled         bool       `json:"-"`
	FLCEnabled         bool       `json:"-"`
	EPCSize            string     `json:"-"`
	TCBUpToDate        bool       `json:"-"`
	Deleted            bool	      `json:"-" gorm:"type:bool;not null;default:false"`
}

type Hosts []Host


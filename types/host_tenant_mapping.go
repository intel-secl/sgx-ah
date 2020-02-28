/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types
import (
        "time"
)

// HostTenantMapping struct is the database schema of a HostTenantMappings table
type HostTenantMapping struct {
	Id                 string     `json:"-" gorm:"type:uuid;unique;primary_key;"`
	HostHardwareUUID   string     `json:"-" gorm:"type:uuid;not null"`
	TenantUUID         string     `json:"-" gorm:"type:uuid"`
	CreatedTime        time.Time  `json:"-"`
	CreatedBy          string     `json:"-"`
	UpdatedTime        time.Time  `json:"-"`
	UpdatedBy          string     `json:"-"`
	Deleted            bool	      `json:"-" gorm:"type:bool;default:false"`
}

type HostTenantMappings []HostTenantMapping


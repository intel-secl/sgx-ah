/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

// HostTenantMapping struct is the database schema of a HostTenantMappings table
type HostTenantMapping struct {
	Id               string    `json:"id" gorm:"type:uuid;unique;primary_key;"`
	HostHardwareUUID string    `json:"host_hardware_uuid" gorm:"type:uuid;not null"`
	TenantUUID       string    `json:"tenant_uuid" gorm:"type:uuid"`
	CreatedTime      time.Time `json:"created_time"`
	CreatedBy        string    `json:"-"`
	UpdatedTime      time.Time `json:"updated_time"`
	UpdatedBy        string    `json:"-"`
	Deleted          bool      `json:"deleted" gorm:"type:bool;not null;default:false"`
}

type HostTenantMappings []HostTenantMapping

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

type SHUBDatabase interface {
	Migrate() error
	HostRepository() HostRepository
	TenantRepository() TenantRepository
	HostTenantMappingRepository() HostTenantMappingRepository
	TenantPluginCredentialRepository() TenantPluginCredentialRepository
	Close()
}

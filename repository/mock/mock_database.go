/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/shub/repository"
)

type MockDatabase struct {
	MockHostRepository                    MockHostRepository
	MockTenantRepository                  MockTenantRepository
	MockHostTenantMappingRepository       MockHostTenantMappingRepository
	MockTenantPluginCredentialRepository  MockTenantPluginCredentialRepository
}

func (m *MockDatabase) Migrate() error {
	return nil
}

func (m *MockDatabase) HostRepository() repository.HostRepository {
	return &m.MockHostRepository
}

func (m *MockDatabase) TenantRepository() repository.TenantRepository {
	return &m.MockTenantRepository
}

func (m *MockDatabase) HostTenantMappingRepository() repository.HostTenantMappingRepository {
	return &m.MockHostTenantMappingRepository
}

func (m *MockDatabase) TenantPluginCredentialRepository() repository.TenantPluginCredentialRepository {
	return &m.MockTenantPluginCredentialRepository
}

func (m *MockDatabase) Close() {
}

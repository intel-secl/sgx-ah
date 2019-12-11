/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

type SAHDatabase interface {
	Migrate() error
	PlatformTcbRepository() PlatformTcbRepository
	PckCertChainRepository() PckCertChainRepository
	PckCertRepository() PckCertRepository
	PckCrlRepository() PckCrlRepository
	FmspcTcbInfoRepository() FmspcTcbInfoRepository
	QEIdentityRepository() QEIdentityRepository
	Close()
}

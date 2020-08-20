/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package scheduler

import (
	"intel/isecl/shub/repository"
	"intel/isecl/shub/resource"
	"intel/isecl/shub/resource/attestationServicePollerJob"
	"os"
	"os/signal"
	"syscall"
	"time"

	clog "intel/isecl/lib/common/v3/log"
)

var log = clog.GetDefaultLogger()
var slog = clog.GetSecurityLogger()

func StartSHUBSchedular(db repository.SHUBDatabase, timer int) {
	log.Trace("scheduler/shub_scheduler: StartSHUBSchedular() Entering")
	defer log.Trace("scheduler/shub_scheduler: StartSHUBSchedular() Leaving")

	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		ticker := time.NewTicker(time.Second * time.Duration(timer))
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				log.Error("scheduler/shub_scheduler: StartSHUBSchedular() Got Signal for exit and exiting.... Refresh Timer")
				break
			case t := <-ticker.C:
				log.Debug("scheduler/shub_scheduler: StartSHUBSchedular() Timer started", t)
				err := SHUBSchedulerJob(db)
				if err != nil {
					log.WithError(err).Info("scheduler/shub_scheduler: StartSHUBSchedular()")
					break
				}
			}
		}
	}()
}

func SHUBSchedulerJob(db repository.SHUBDatabase) error {
	log.Trace("scheduler/shub_scheduler: SHUBSchedulerJob() Entering")
	defer log.Trace("scheduler/shub_scheduler: SHUBSchedulerJob() Leaving")

	log.Info("scheduler/shub_scheduler: SHUBSchedulerJob() Executing scheduled process of pulling data from attestation service and pushing to tenants")

	err := attestationServicePollerJob.Execute(db)
	if err != nil {
		log.WithError(err).Error("scheduler/shub_scheduler: SHUBSchedulerJob() Error while running poller job")
	}

	err = resource.SynchAttestationInfo(db)
	if err != nil {
		log.Info("got error")
		log.Error("scheduler/shub_scheduler: SHUBSchedulerJob() Error while pushing data to the tenant")
	}
	return nil
}

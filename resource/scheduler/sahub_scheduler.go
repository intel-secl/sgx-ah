/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package scheduler

import (
	"intel/isecl/sgx-attestation-hub/repository"
	"intel/isecl/sgx-attestation-hub/resource"
	"os"
	"os/signal"
	"syscall"
	"time"

	clog "intel/isecl/lib/common/log"
)

var log = clog.GetDefaultLogger()
var slog = clog.GetSecurityLogger()

func StartSAHSchedular(db repository.SAHDatabase, timer int) {
	log.Trace("scheduler/sah_scheduler: StartSAHSchedular() Entering")
	defer log.Trace("scheduler/sah_scheduler: StartSAHSchedular() Leaving")

	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		ticker := time.NewTicker(time.Second * time.Duration(timer))
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				log.Error("scheduler/sah_scheduler: StartSAHSchedular() Got Signal for exit and exiting.... Refresh Timer")
				break
			case t := <-ticker.C:
				log.Debug("scheduler/sah_scheduler: StartSAHSchedular() Timer started", t)
				err := SAHSchedulerJob(db)
				if err != nil {
					log.Error("scheduler/sah_scheduler: StartSAHSchedular() :" + err.Error())
					break
				}
			}
		}
	}()
}

func SAHSchedulerJob(db repository.SAHDatabase) error {
	log.Trace("scheduler/sah_scheduler: SAHSchedulerJob() Entering")
	defer log.Trace("scheduler/sah_scheduler: SAHSchedulerJob() Leaving")

	log.Info("scheduler/sah_scheduler: SAHSchedulerJob() Executing scheduled process of pulling data from attestation service and pushing to tenants")

	//TODO:
	/*
		err := attestationServicePollerJob.execute();
		if err != nil {
			log.Error("scheduler/sah_scheduler: SAHSchedulerJob() Error while running poller job")
		}
	*/
	err := resource.SynchAttestationInfo(db)
	if err != nil {
		log.Error("scheduler/sah_scheduler: SAHSchedulerJob() Error while pushing data to the tenant")
	}
	return nil
}

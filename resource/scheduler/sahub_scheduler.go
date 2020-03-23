/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package scheduler

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	clog "intel/isecl/lib/common/log"
)

var log = clog.GetDefaultLogger()
var slog = clog.GetSecurityLogger()

func StartSAHUBSchedular(timer int) {
	log.Trace("scheduler/sahub_scheduler: StartSAHUBSchedular() Entering")
	defer log.Trace("scheduler/sahub_scheduler: StartSAHUBSchedular() Leaving")

	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		ticker := time.NewTicker(time.Second * time.Duration(timer))
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				log.Error("scheduler/sahub_scheduler: StartSAHUBSchedular() Got Signal for exit and exiting.... Refresh Timer")
				break
			case t := <-ticker.C:
				log.Debug("scheduler/sahub_scheduler: StartSAHUBSchedular() Timer started", t)
				err := SAHUBSchedulerJob()
				if err != nil {
					log.Error("scheduler/sahub_scheduler: StartSAHUBSchedular() :" + err.Error())
					break
				}
			}
		}
	}()
}

func SAHUBSchedulerJob() error {
	log.Trace("scheduler/sahub_scheduler: SAHUBSchedulerJob() Entering")
	defer log.Trace("scheduler/sahub_scheduler: SAHUBSchedulerJob() Leaving")

	log.Info("scheduler/sahub_scheduler: SAHUBSchedulerJob() Executing scheduled process of pulling data from attestation service and pushing to tenants")

	//TODO:
	//attestationServicePollerJob.execute();
	//pluginManager.synchAttestationInfo();

	return nil
}


/**
 * ACME / Let's Encrypt client — DNS-01 challenge via DuckDNS.
 * Obtains and renews TLS certificates automatically.
 */
#ifndef SPANGAP_ACME_H
#define SPANGAP_ACME_H

#include "service.h"

/** The ACME service. onInit registers ACME CLI commands at boot. */
class AcmeService : public Service {
public:
    void onInit() override;
};

/** Check if cert needs renewal (minDays = threshold for remaining days).
 *  Spawns temp task and waits if renewal needed.
 *  Called from main after waitForTime() (needs valid time + network). */
void acmeCheck(int minDays = 30);

#endif

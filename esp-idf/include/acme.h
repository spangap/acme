/**
 * ACME / Let's Encrypt client — DNS-01 challenge via DuckDNS.
 * Obtains and renews TLS certificates automatically.
 */
#ifndef SECCAM_ACME_H
#define SECCAM_ACME_H

/** Register ACME CLI commands. Call from main. */
void acmeInit();

/** Check if cert needs renewal (minDays = threshold for remaining days).
 *  Spawns temp task and waits if renewal needed.
 *  Called from main after waitForTime() (needs valid time + network). */
void acmeCheck(int minDays = 30);

#endif

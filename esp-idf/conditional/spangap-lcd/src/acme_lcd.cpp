/**
 * acme_lcd.cpp — on-device Settings → Net → ACME pane (LVGL).
 *
 * Mirrors the browser AcmePanel. Runs on the lcd task; storage keys must be
 * static (the lcdSetting* helpers store them by pointer).
 *
 * This whole file lives under conditional/spangap-lcd/, compiled only when the
 * spangap-lcd straddle is staged, so no lcd-staging #if guard is needed.
 * Registers via the when:-gated acmeLcdRegister hook (plain C++ linkage to match
 * the generated dispatcher's forward decl).
 */
#include "lcd.h"

/* On-device Settings → Net → ACME pane. Mirrors the browser AcmePanel. Runs on
 * the lcd task; storage keys must be static (the helpers store them by pointer). */
static void acmeSettingsPane(void* arg) {
    lv_obj_t* p = static_cast<lv_obj_t*>(arg);
    lcdSettingSection (p, "ACME");
    lcdSettingSwitch  (p, "Enable",    "s.acme.enable");
    lcdSettingText    (p, "Domain",    "s.net.dns.fqdn");
#if CONFIG_SPANGAP_WEB
    lcdSettingDropdown(p, "Method",    "s.acme.method", ",DNS-01,HTTP-01");
#else
    /* No HTTP-01 in this build — present DNS-01 as the only option. */
    lcdSettingDropdown(p, "Method",    "s.acme.method", ",DNS-01");
#endif
    lcdSettingText    (p, "Directory", "s.acme.url");
}

/* Register the on-device ACME settings pane — a when:-gated init: hook
 * (spangap/spangap-lcd). */
void acmeLcdRegister(void) {
    lcdRegisterSettings("Internet/ACME", "ACME", acmeSettingsPane);
}

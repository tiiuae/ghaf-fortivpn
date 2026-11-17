// SPDX-FileCopyrightText: 2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

#include <openconnect.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

extern int ghaf_check_certificate(void *, const unsigned char *, int);
extern int ghaf_answer(void *, int, const char *, const char *, const char *, int,
                       char *, unsigned int);
extern int ghaf_result(void *, const char *, const char *, const char *,
                       const char *, const char *);

struct authentication {
    struct openconnect_info *vpn;
    void *context;
};

static void quiet_progress(void *data, int level, const char *fmt, ...) {
    (void)data;
    (void)level;
    (void)fmt;
}

static int validate_peer(void *data, const char *reason) {
    struct authentication *auth = data;
    unsigned char *der = NULL;
    int length = openconnect_get_peer_cert_DER(auth->vpn, &der);
    int result = -1;
    (void)reason;
    if (length > 0)
        result = ghaf_check_certificate(auth->context, der, length);
    if (der)
        openconnect_free_cert_info(auth->vpn, der);
    return result;
}

static int process_form(void *data, struct oc_auth_form *form) {
    struct authentication *auth = data;
    unsigned int count = 0;
    int login = 0;
    for (struct oc_form_opt *opt = form->opts; opt; opt = opt->next) {
        if (form->auth_id && !strcmp(form->auth_id, "_login") &&
            opt->type == OC_FORM_OPT_TEXT && opt->name && !strcmp(opt->name, "username"))
            login = 1;
    }
    for (struct oc_form_opt *opt = form->opts; opt; opt = opt->next) {
        char answer[4097] = {0};
        if (++count > 32)
            return OC_FORM_RESULT_ERR;
        if ((opt->flags & OC_FORM_OPT_IGNORE) || opt->type == OC_FORM_OPT_HIDDEN)
            continue;
        if (opt->type != OC_FORM_OPT_TEXT && opt->type != OC_FORM_OPT_PASSWORD &&
            opt->type != OC_FORM_OPT_TOKEN)
            return OC_FORM_RESULT_ERR;
        int result = ghaf_answer(auth->context, login, opt->name,
                                 opt->label, form->error ? form->error : form->message,
                                 opt->type != OC_FORM_OPT_TEXT,
                                 answer, sizeof(answer));
        if (!result)
            result = openconnect_set_option_value(opt, answer);
        explicit_bzero(answer, sizeof(answer));
        if (result)
            return OC_FORM_RESULT_CANCELLED;
    }
    return OC_FORM_RESULT_OK;
}

int ghaf_openconnect(void *context, const char *gateway, const char *certificate,
                     const char *key, const char *ca) {
    struct authentication auth = {.context = context};
    int result = -1;
    if (openconnect_init_ssl())
        return -1;
    auth.vpn = openconnect_vpninfo_new("Ghaf FortiVPN", validate_peer, NULL,
                                      process_form, quiet_progress, &auth);
    if (!auth.vpn)
        return -1;
    if (openconnect_set_protocol(auth.vpn, "fortinet") ||
        openconnect_parse_url(auth.vpn, gateway) ||
        (*ca && openconnect_set_cafile(auth.vpn, ca)) ||
        (*certificate && openconnect_set_client_cert(auth.vpn, certificate, key)))
        goto out;
    result = openconnect_obtain_cookie(auth.vpn);
    if (!result)
        result = ghaf_result(context, openconnect_get_cookie(auth.vpn),
                             openconnect_get_connect_url(auth.vpn),
                             openconnect_get_peer_cert_hash(auth.vpn),
                             openconnect_get_dnsname(auth.vpn),
                             openconnect_get_hostname(auth.vpn));
out:
    openconnect_vpninfo_free(auth.vpn);
    return result;
}

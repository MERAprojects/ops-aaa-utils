/* support.c - support functions for pam_tacplus.c
 *
 * Copyright (C) 2016-2017 Hewlett Packard Enterprise Development LP.
 * Copyright (C) 2010, Pawel Krawczyk <pawel.krawczyk@hush.com> and
 * Jeroen Nijhof <jeroen@jeroennijhof.nl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program - see the file COPYING.
 *
 * See `CHANGES' file for revision history.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include "support.h"
#include "pam_tacplus.h"

#include <stdlib.h>
#include <string.h>

#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "nl-utils.h"

tacplus_server_t tac_srv[TAC_PLUS_MAXSERVERS];
int tac_srv_no = 0;

char tac_service[64];
char tac_protocol[64];
char tac_prompt[64];

char tac_dstn_namespace[64];

char tac_source_ip[64];

extern int setns(int fd, int nstype);

void _pam_log(int err, const char *format,...) {
    char msg[256];
    va_list args;

    va_start(args, format);
    vsnprintf(msg, sizeof(msg), format, args);
    openlog("PAM-tacplus", LOG_PID, LOG_AUTH);
    syslog(err, "%s", msg);
    va_end(args);
    closelog();
}

char *_pam_get_user(pam_handle_t *pamh) {
    int retval;
    char *user;

    retval = pam_get_user(pamh, (void *)&user, "Username: ");
    if (retval != PAM_SUCCESS || user == NULL || *user == '\0') {
        _pam_log(LOG_ERR, "unable to obtain username");
        user = NULL;
    }
    return user;
}

char *_pam_get_terminal(pam_handle_t *pamh) {
    int retval;
    char *tty;

    retval = pam_get_item(pamh, PAM_TTY, (void *)&tty);
    if (retval != PAM_SUCCESS || tty == NULL || *tty == '\0') {
        tty = ttyname(STDIN_FILENO);
        if(tty == NULL || *tty == '\0')
            tty = "unknown";
    }
    return tty;
}

char *_pam_get_rhost(pam_handle_t *pamh) {
    int retval;
    char *rhost;

    retval = pam_get_item(pamh, PAM_RHOST, (void *)&rhost);
    if (retval != PAM_SUCCESS || rhost == NULL || *rhost == '\0') {
        rhost = "unknown";
    }
    return rhost;
}

int converse(pam_handle_t * pamh, int nargs, const struct pam_message *message,
    struct pam_response **response) {

    int retval;
    struct pam_conv *conv;

    if ((retval = pam_get_item (pamh, PAM_CONV, (const void **)&conv)) == PAM_SUCCESS) {
        retval = conv->conv(nargs, &message, response, conv->appdata_ptr);

        if (retval != PAM_SUCCESS) {
            _pam_log(LOG_ERR, "(pam_tacplus) converse returned %d", retval);
            _pam_log(LOG_ERR, "that is: %s", pam_strerror (pamh, retval));
        }
    } else {
        _pam_log (LOG_ERR, "(pam_tacplus) converse failed to get pam_conv");
    }

    return retval;
}

/* stolen from pam_stress */
int tacacs_get_password (pam_handle_t * pamh, int flags
    ,int ctrl, char **password) {

    const void *pam_pass;
    char *pass = NULL;

    if (ctrl & PAM_TAC_DEBUG)
        syslog (LOG_DEBUG, "%s: called", __FUNCTION__);

    if ( (ctrl & (PAM_TAC_TRY_FIRST_PASS | PAM_TAC_USE_FIRST_PASS))
        && (pam_get_item(pamh, PAM_AUTHTOK, &pam_pass) == PAM_SUCCESS)
        && (pam_pass != NULL) ) {
         if ((pass = strdup(pam_pass)) == NULL)
              return PAM_BUF_ERR;
    } else if ((ctrl & PAM_TAC_USE_FIRST_PASS)) {
         _pam_log(LOG_WARNING, "no forwarded password");
         return PAM_PERM_DENIED;
    } else {
         struct pam_message msg;
         struct pam_response *resp = NULL;
         int retval;

         /* set up conversation call */
         msg.msg_style = PAM_PROMPT_ECHO_OFF;

         if (!tac_prompt[0]) {
             msg.msg = "Password: ";
         } else {
             msg.msg = tac_prompt;
         }

         if ((retval = converse (pamh, 1, &msg, &resp)) != PAM_SUCCESS)
             return retval;

         if (resp != NULL) {
             if (resp->resp == NULL && (ctrl & PAM_TAC_DEBUG))
                 _pam_log (LOG_DEBUG, "pam_sm_authenticate: NULL authtok given");

             pass = resp->resp;    /* remember this! */
             resp->resp = NULL;

             free(resp);
             resp = NULL;
         } else {
             if (ctrl & PAM_TAC_DEBUG) {
               _pam_log (LOG_DEBUG, "pam_sm_authenticate: no error reported");
               _pam_log (LOG_DEBUG, "getting password, but NULL returned!?");
             }
             return PAM_CONV_ERR;
         }
    }

    /*
       FIXME *password can still turn out as NULL
       and it can't be free()d when it's NULL
    */
    *password = pass;       /* this *MUST* be free()'d by this module */

    if(ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: obtained password", __FUNCTION__);

    return PAM_SUCCESS;
}

int _pam_parse (int argc, const char **argv) {
    int ctrl = 0;
    const char *current_secret = NULL;

    /* otherwise the list will grow with each call */
    memset(tac_srv, 0, sizeof(tacplus_server_t) * TAC_PLUS_MAXSERVERS);
    tac_srv_no = 0;

    tac_service[0] = 0;
    tac_protocol[0] = 0;
    tac_prompt[0] = 0;
    tac_login[0] = 0;

    tac_dstn_namespace[0] = 0;
    tac_source_ip[0] = 0;

    for (ctrl = 0; argc-- > 0; ++argv) {
        if (!strcmp (*argv, "debug")) { /* all */
            ctrl |= PAM_TAC_DEBUG;
        } else if (!strcmp (*argv, "use_first_pass")) {
            ctrl |= PAM_TAC_USE_FIRST_PASS;
        } else if (!strcmp (*argv, "try_first_pass")) {
            ctrl |= PAM_TAC_TRY_FIRST_PASS;
        } else if (!strncmp (*argv, "service=", strlen("service="))) { /* author & acct */
            strncpy (tac_service, *argv + strlen("service="), sizeof(tac_service));
        } else if (!strncmp (*argv, "protocol=", strlen("protocol="))) { /* author & acct */
            strncpy (tac_protocol, *argv + strlen("protocol="), sizeof(tac_protocol));
        } else if (!strncmp (*argv, "prompt=", strlen("prompt="))) { /* authentication */
            strncpy (tac_prompt, *argv + strlen("prompt="), sizeof(tac_prompt));
            /* Replace _ with space */
            int chr;
            for (chr = 0; chr < strlen(tac_prompt); chr++) {
                if (tac_prompt[chr] == '_') {
                    tac_prompt[chr] = ' ';
                }
            }
        } else if (!strncmp (*argv, "login=", strlen("login="))) {
            strncpy (tac_login, *argv + strlen("login="), sizeof(tac_login));
        } else if (!strcmp (*argv, "acct_all")) {
            ctrl |= PAM_TAC_ACCT;
        } else if (!strcmp (*argv, "bypass_acct")) {
            ctrl |= PAM_TAC_BYPASS_ACCT;
        } else if (!strcmp (*argv, "bypass_session")) {
            ctrl |= PAM_TAC_BYPASS_SESSION;
        } else if (!strncmp (*argv, "server=", strlen("server="))) { /* authen & acct */
            if(tac_srv_no < TAC_PLUS_MAXSERVERS) {
                struct addrinfo hints, *servers, *server;
                int rv;
                char *close_bracket, *server_name, *port, server_buf[256];

                memset(&hints, 0, sizeof hints);
                hints.ai_family = AF_UNSPEC;  /* use IPv4 or IPv6, whichever */
                hints.ai_socktype = SOCK_STREAM;

                if (strlen(*argv + 7) >= sizeof(server_buf)) {
                    _pam_log(LOG_ERR, "server address too long, sorry");
                    continue;
                }
                strcpy(server_buf, *argv + 7);

                if (*server_buf == '[' && (close_bracket = strchr(server_buf, ']')) != NULL) { /* Check for URI syntax */
                    server_name = server_buf + 1;
                    port = strchr(close_bracket, ':');
                    *close_bracket = '\0';
                } else { /* Fall back to traditional syntax */
                    server_name = server_buf;
                    port = strchr(server_buf, ':');
                }
                if (port != NULL) {
                    *port = '\0';
                    port++;
                }
                if ((rv = getaddrinfo(server_name, (port == NULL) ? "49" : port, &hints, &servers)) == 0) {
                    for(server = servers; server != NULL && tac_srv_no < TAC_PLUS_MAXSERVERS; server = server->ai_next) {
                        tac_srv[tac_srv_no].addr = server;
                        tac_srv[tac_srv_no].key = current_secret;
                        tac_srv_no++;
                    }
                } else {
                    _pam_log (LOG_ERR,
                        "skip invalid server: %s (getaddrinfo: %s)",
                        server_name, gai_strerror(rv));
                }
            } else {
                _pam_log(LOG_ERR, "maximum number of servers (%d) exceeded, skipping",
                    TAC_PLUS_MAXSERVERS);
            }
        } else if (!strncmp (*argv, "secret=", strlen("secret="))) {
            int i;

            current_secret = *argv + strlen("secret=");     /* points right into argv (which is const) */

            /* if 'secret=' was given after a 'server=' parameter, fill in the current secret */
            for(i = tac_srv_no-1; i >= 0; i--) {
                if (tac_srv[i].key != NULL)
                    break;

                tac_srv[i].key = current_secret;
            }
        } else if (!strncmp (*argv, "timeout=", strlen("timeout="))) {
            /* FIXME atoi() doesn't handle invalid numeric strings well */
            tac_timeout = atoi(*argv + strlen("timeout="));

            if (tac_timeout < 0) {
                tac_timeout = 0;
            } else {
                tac_readtimeout_enable = 1;
            }
        } else if (!strncmp (*argv, "dstn_namespace=", strlen("dstn_namespace="))) {
            /* destination namespace */
            strncpy (tac_dstn_namespace, *argv + strlen("dstn_namespace="), sizeof(tac_dstn_namespace));
        } else if (!strncmp (*argv, "source_ip=", strlen("source_ip="))) {
            /* source ip for the packets */
            strncpy (tac_source_ip, *argv + strlen("source_ip="), sizeof(tac_source_ip));
        } else {
            _pam_log (LOG_WARNING, "unrecognized option: %s", *argv);
        }
    }

    if (ctrl & PAM_TAC_DEBUG) {
        int n;

        _pam_log(LOG_DEBUG, "%d servers defined", tac_srv_no);

        for(n = 0; n < tac_srv_no; n++) {
            _pam_log(LOG_DEBUG, "server[%d] { addr=%s, key='%s' }", n, tac_ntop(tac_srv[n].addr->ai_addr), tac_srv[n].key);
        }

        _pam_log(LOG_DEBUG, "tac_service='%s'", tac_service);
        _pam_log(LOG_DEBUG, "tac_protocol='%s'", tac_protocol);
        _pam_log(LOG_DEBUG, "tac_prompt='%s'", tac_prompt);
        _pam_log(LOG_DEBUG, "tac_login='%s'", tac_login);
        _pam_log(LOG_DEBUG, "tac_dstn_namespace='%s'", tac_dstn_namespace);
        _pam_log(LOG_DEBUG, "tac_source_ip='%s'", tac_source_ip);
    }

    return ctrl;
}    /* _pam_parse */

/* set source ip address for the outgoing tacacs packets */
void set_source_ip(const char *tac_source_ip,
    struct addrinfo **source_address) {

    struct addrinfo hints;
    int rv;

    /* set the source ip address for the tacacs packets */
    if (tac_source_ip != NULL) {
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if ((rv = getaddrinfo(tac_source_ip, "tacacs", &hints,
             source_address)) != 0) {
            _pam_log(LOG_ERR, "error setting the source ip information");
        } else {
            _pam_log(LOG_DEBUG, "source ip is set");
        }
    }
}

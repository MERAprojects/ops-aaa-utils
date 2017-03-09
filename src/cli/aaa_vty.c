/* AAA CLI commands.
 *
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 * Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
 *
 * This Program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * File: aaa_vty.c
 *
 * Purpose:  To add AAA CLI configuration and display commands.
 */

#include <sys/un.h>
#include <setjmp.h>
#include <sys/wait.h>
#include <pwd.h>

#include <readline/readline.h>
#include <readline/history.h>

#include <lib/version.h>
#include "getopt.h"
#include "vtysh/command.h"
#include "vtysh/memory.h"
#include "vtysh/vtysh.h"
#include "vtysh/vtysh_user.h"
#include "vswitch-idl.h"
#include "ovsdb-idl.h"
#include "aaa_vty.h"
#include "smap.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vtysh/utils/tacacs_vtysh_utils.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "vtysh/utils/ovsdb_vtysh_utils.h"
#include "vtysh_ovsdb_aaa_context.h"
#include <arpa/inet.h>
#include <string.h>

extern struct ovsdb_idl *idl;

static int aaa_show_aaa_authentication ();
static int set_global_auth_type(const char *auth_type, const bool is_tacacs_server);
static int set_global_passkey (const char *passkey, const bool is_tacacs_server);
static int set_global_timeout (const char *timeout, const bool is_tacacs_server);
static int set_global_retries (const char *retries);
static const struct ovsrec_aaa_server_group*
           get_row_by_server_group_name(const char *name);
static const struct ovsrec_tacacs_server*
           get_tacacs_server_by_name_port(const char *server_name, int64_t auth_port);
static int show_aaa_authentication_priority_group();
static int show_aaa_authorization_priority_group();
static int show_auto_provisioning ();
static int show_ssh_auth_method ();
static int set_ssh_publickey_auth (const char *status);
static int set_ssh_password_auth (const char *status);

VLOG_DEFINE_THIS_MODULE(vtysh_aaa_cli);

/* AAA server group utility functions*/
static const struct ovsrec_aaa_server_group*
get_row_by_server_group_name(const char *name)
{
    const struct ovsrec_aaa_server_group *row = NULL;
    OVSREC_AAA_SERVER_GROUP_FOR_EACH(row, idl) {
        if(VTYSH_STR_EQ(row->group_name, name))
        {
            return row;
        }
    }
    return NULL;
}

const bool
server_group_exists(const char *name)
{
    return get_row_by_server_group_name(name) != NULL;
}

const int
configure_aaa_server_group_priority(aaa_server_group_prio_params_t *group_prio_params)
{
    struct ovsdb_idl_txn *priority_txn = NULL;
    const struct ovsrec_aaa_server_group *group_row = NULL;
    const struct ovsrec_aaa_server_group_prio *group_prio_default = NULL;
    int64_t priority = 0;
    int iter = 0;
    int64_t *key_list = NULL;
    struct ovsrec_aaa_server_group **value_list = NULL;
    int64_t group_count = group_prio_params->group_count;
    /* Start of transaction */
    START_DB_TXN(priority_txn);

    group_prio_default = ovsrec_aaa_server_group_prio_first(idl);

    if (group_prio_default == NULL)
    {
        ERRONEOUS_DB_TXN(priority_txn, "Could not access 'default' entry of AAA_Server_Group_Prio Table");
    }

    /* Reset local group priority to 0 for no version of command */
    if (group_prio_params->no_form)
    {
        if (group_prio_params->aaa_method == authentication)
        {
            group_row = get_row_by_server_group_name(SYSTEM_AAA_LOCAL);
        }
        else if (group_prio_params->aaa_method == authorization)
        {
            group_row = get_row_by_server_group_name(SYSTEM_AAA_NONE);
        }

        if (group_row == NULL)
        {
            ERRONEOUS_DB_TXN(priority_txn, "AAA server group does not exist.");
        }
        key_list = malloc(sizeof(int64_t));
        value_list = malloc(sizeof(*group_row));
        if (!key_list || !value_list)
        {
            if (key_list) free(key_list);
            if (value_list) free(value_list);
            ERRONEOUS_DB_TXN(priority_txn, "Malloc failed.");
        }
        key_list[0] = priority;
        value_list[0] = (struct ovsrec_aaa_server_group *)group_row;
        group_count = 1;
    }

    else
    {
        priority = 1;
        key_list = malloc(sizeof(int64_t) * group_count);
        value_list = malloc(sizeof(*group_row) * group_count);
        if (!key_list || !value_list)
        {
            if (key_list) free(key_list);
            if (value_list) free(value_list);
            ERRONEOUS_DB_TXN(priority_txn, "Malloc failed.");
        }
        for (iter = 0; iter < group_count; iter++)
        {
            group_row = get_row_by_server_group_name(group_prio_params->group_list[iter]);

            if (group_row == NULL)
            {
                free(key_list);
                free(value_list);
                ERRONEOUS_DB_TXN(priority_txn, "AAA server group does not exist.");
            }

            // RADIUS and Local AAA groups are not allowed with AAA command authorization
            if (group_prio_params->aaa_method == authorization && \
                (VTYSH_STR_EQ(group_row->group_type,SYSTEM_AAA_RADIUS) || \
                VTYSH_STR_EQ(group_row->group_type,SYSTEM_AAA_LOCAL)))
            {
                free(key_list);
                free(value_list);
                ERRONEOUS_DB_TXN(priority_txn, "Incorrect command authorization configuration, \
                    please use only 'none' or tacacs_plus AAA server groups");
            }

            // None group is not allowed to be configured with AAA authentication
            if (group_prio_params->aaa_method == authentication && \
                VTYSH_STR_EQ(group_row->group_type,SYSTEM_AAA_NONE))
            {
                free(key_list);
                free(value_list);
                ERRONEOUS_DB_TXN(priority_txn, "Incorrect command authorization configuration, \
                    please use only 'none' or tacacs_plus AAA server groups");
            }

            key_list[iter] = priority;
            value_list[iter] = (struct ovsrec_aaa_server_group *)group_row;
            priority ++;
        }
    }

    if (group_prio_params->aaa_method == authentication)
    {
        ovsrec_aaa_server_group_prio_set_authentication_group_prios(group_prio_default,
                                                                key_list, value_list,
                                                                group_count);
    }
    else
    {
        ovsrec_aaa_server_group_prio_set_authorization_group_prios(group_prio_default,
                                                                key_list, value_list,
                                                                group_count);
    }

    free(key_list);
    free(value_list);
    /* End of transaction. */
    END_DB_TXN(priority_txn);
}

DEFUN(cli_aaa_set_authentication,
      aaa_set_authentication_cmd,
      "aaa authentication login default {local | group .WORD}",
      AAA_STR
      AAA_AUTHENTICATION_HELP_STR
      AAA_LOGIN_HELP_STR
      AAA_DEFAULT_AUTHEN_LINE_HELP_STR
      AAA_LOCAL_AUTHENTICATION_HELP_STR
      GROUP_HELP_STR
      GROUP_NAME_AUTH_HELP_STR)

{
    char **group_list = NULL;
    int group_count = 0;
    int keyword_skip = 0;
    aaa_server_group_prio_params_t group_prio_params;
    int rv = 0;

    /*
     * because of current args implementation,
     * we have to check this condition manually
     */
    if ( argv[0] == NULL && argv[1] == NULL )
    {
        vty_out (vty, "%% Command incomplete.%s", VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    }

    /* we need this check to take care of the no form */
    if (argc >= 1)
    {
        /* check if the first argv is group or local and set group count*/
        if ( !argv[0] || VTYSH_STR_EQ(argv[0], AAA_GROUP))
        {
           keyword_skip = 1;
           group_count = argc - keyword_skip;
        }
        else if (VTYSH_STR_EQ(argv[0], SYSTEM_AAA_LOCAL))
        {
           group_count = 1;
        }
        group_list = malloc(sizeof(char *) * group_count);
        if (!group_list)
        {
            VLOG_ERR("Malloc failed.");
            return CMD_ERR_NOTHING_TODO;
        }
        memcpy(group_list, argv + keyword_skip, sizeof(char *) * group_count);
    }

    group_prio_params.no_form = false;
    group_prio_params.group_count = group_count;
    group_prio_params.group_list = group_list;
    group_prio_params.aaa_method = authentication;
    group_prio_params.login_type = AAA_SERVER_GROUP_PRIO_SESSION_TYPE_DEFAULT;

    if (vty_flags & CMD_FLAG_NO_CMD)
    {
        group_prio_params.no_form = true;
    }

    rv = configure_aaa_server_group_priority(&group_prio_params);
    free(group_list);
    return rv;
}

DEFUN_NO_FORM(cli_aaa_set_authentication,
              aaa_set_authentication_cmd,
              "aaa authentication login default",
              AAA_STR
              AAA_AUTHENTICATION_HELP_STR
              AAA_LOGIN_HELP_STR
              AAA_DEFAULT_AUTHEN_LINE_HELP_STR);

const static int
set_aaa_fail_through(bool allow_fail_through)
{
    const struct ovsrec_system *row = NULL;
    struct ovsdb_idl_txn *status_txn = NULL;
    struct smap smap_aaa;

    /* Start of transaction */
    START_DB_TXN(status_txn);

    row = ovsrec_system_first(idl);

    if (row == NULL)
    {
        ERRONEOUS_DB_TXN(status_txn, "Could not access the System Table");
    }

    smap_clone(&smap_aaa, &row->aaa);

    smap_replace(&smap_aaa, SYSTEM_AAA_FAIL_THROUGH,
                 allow_fail_through ? AAA_TRUE_FLAG_STR : AAA_FALSE_FLAG_STR);

    ovsrec_system_set_aaa(row, &smap_aaa);

    smap_destroy(&smap_aaa);

    /* End of transaction */
    END_DB_TXN(status_txn);
}

/* CLI to enable fail-through */
DEFUN(cli_aaa_allow_fail_through,
      aaa_allow_fail_through_cmd,
      "aaa authentication allow-fail-through",
      AAA_STR
      AAA_AUTHENTICATION_HELP_STR
      AAA_ALLOW_FAIL_THROUGH_HELP_STR)
{
    bool allow_fail_through = true;

    if (CMD_FLAG_NO_CMD & vty_flags) {
        allow_fail_through = false;
    }

    return set_aaa_fail_through(allow_fail_through);
}

/* CLI to disable fail-through  */
DEFUN_NO_FORM (cli_aaa_allow_fail_through,
               aaa_allow_fail_through_cmd,
               "aaa authentication allow-fail-through",
               AAA_STR
               AAA_AUTHENTICATION_HELP_STR
               AAA_ALLOW_FAIL_THROUGH_HELP_STR);


/* Displays AAA Authentication configuration.
 * Shows status of the local authentication [Enabled/Disabled]
 * Shows status of the Radius authentication [Enabled/Disabled]
 * If Radius authentication is enabled, shows Radius authentication
 * type [pap/chap]
 */
static int
aaa_show_aaa_authentication()
{
    const struct ovsrec_system *row = NULL;

    row = ovsrec_system_first(idl);

    if (!row)
    {
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    vty_out(vty, "AAA Authentication:%s", VTY_NEWLINE);

    /* Display fail-through status */
    if (VTYSH_STR_EQ(smap_get(&row->aaa, SYSTEM_AAA_FAIL_THROUGH), AAA_TRUE_FLAG_STR))
    {
        vty_out(vty, "  Fail-through\t\t\t\t: %s%s", "Enabled", VTY_NEWLINE);
    }
    else
    {
        vty_out(vty, "  Fail-through\t\t\t\t: %s%s", "Disabled", VTY_NEWLINE);
    }

    return show_aaa_authentication_priority_group();
}

static int
show_aaa_authentication_priority_group()
{
    int count = 0;
    const struct ovsrec_aaa_server_group *group_row = NULL;
    const struct ovsrec_aaa_server_group_prio *group_prio_list = NULL;

    group_prio_list = ovsrec_aaa_server_group_prio_first(idl);

    if (!group_prio_list)
    {
      return CMD_SUCCESS;
    }

    count = group_prio_list->n_authentication_group_prios;

    if (count > 0)
    {
        int idx = 0;
        char row_separator[AAA_TABLE_WIDTH + 1] = {};
        int64_t priority = 0;

        if (!ovsrec_aaa_server_group_first(idl))
        {
            return CMD_SUCCESS;
        }

        /* Create row seperator string*/
        for(idx = 0; idx < AAA_TABLE_WIDTH; idx++)
            row_separator[idx] = '-';
        row_separator[AAA_TABLE_WIDTH] = '\0';

        vty_out(vty, "%sDefault Authentication for All Channels:%s", VTY_NEWLINE, VTY_NEWLINE);
        vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
        vty_out(vty, "%-32s | %-14s%s", "GROUP NAME", "GROUP PRIORITY", VTY_NEWLINE);
        vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
        for(idx = 0; idx < count; idx ++)
        {
            priority = group_prio_list->key_authentication_group_prios[idx];
            group_row = group_prio_list->value_authentication_group_prios[idx];
            vty_out(vty, "%-32s | %-14"PRId64"%s", group_row->group_name, priority, VTY_NEWLINE);
        }
    }

    return CMD_SUCCESS;
}
/* CLI to show authentication mechanism configured in DB. */
DEFUN(cli_aaa_show_aaa_authentication,
        aaa_show_aaa_authentication_cmd,
        "show aaa authentication",
        SHOW_STR
        "Show authentication options\n" "Show aaa authentication information\n")
{
    return aaa_show_aaa_authentication();
}

static int
show_aaa_authorization_priority_group()
{
    int count = 0;
    const struct ovsrec_aaa_server_group *group_row = NULL;
    const struct ovsrec_aaa_server_group_prio *group_prio_list = NULL;

    group_prio_list = ovsrec_aaa_server_group_prio_first(idl);

    if (!group_prio_list)
    {
      return CMD_SUCCESS;
    }

    count = group_prio_list->n_authorization_group_prios;

    if (count > 0)
    {
        int idx = 0;
        char row_separator[AAA_TABLE_WIDTH + 1] = {};
        int64_t priority = 0;

        if (!ovsrec_aaa_server_group_first(idl))
        {
            return CMD_SUCCESS;
        }

        /* Create row seperator string*/
        for(idx = 0; idx < AAA_TABLE_WIDTH; idx++)
            row_separator[idx] = '-';
        row_separator[AAA_TABLE_WIDTH] = '\0';

        vty_out(vty, "%sDefault command Authorization for All Channels:%s", VTY_NEWLINE, VTY_NEWLINE);
        vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
        vty_out(vty, "%-32s | %-14s%s", "GROUP NAME", "GROUP PRIORITY", VTY_NEWLINE);
        vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
        for(idx = 0; idx < count; idx ++)
        {
            priority = group_prio_list->key_authorization_group_prios[idx];
            group_row = group_prio_list->value_authorization_group_prios[idx];
            vty_out(vty, "%-32s | %-14"PRId64"%s", group_row->group_name, priority, VTY_NEWLINE);
        }
    }

    return CMD_SUCCESS;
}


/* CLI to show authorization mechanism configured in DB. */
DEFUN(cli_aaa_show_aaa_authorization,
        aaa_show_aaa_authorization_cmd,
        "show aaa authorization",
        SHOW_STR
        "Show authorization options\n" "Show aaa authorization information\n")
{
    return show_aaa_authorization_priority_group();
}

DEFUN(cli_aaa_set_authorization,
      aaa_set_authorization_cmd,
      "aaa authorization commands default {none | group .WORD}",
      AAA_STR
      AAA_USER_AUTHOR_STR
      AAA_COMMAND_AUTHOR_STR
      AAA_DEFAULT_AUTHOR_LINE_HELP_STR
      AAA_NONE_AUTHOR_HELP_STR
      GROUP_HELP_STR
      GROUP_NAME_AUTHOR_HELP_STR)

{
    char **group_list = NULL;
    int group_count = 0;
    int grp_keyword_index = 1;
    int rv = 0;

    aaa_server_group_prio_params_t group_prio_params;
    memset(&group_prio_params, 0, sizeof(group_prio_params));

    /* Taking care of the no form of the command*/
    if (vty_flags & CMD_FLAG_NO_CMD)
    {
        group_prio_params.no_form = true;
        if (argc >= 1)
        {
            vty_out (vty, "Unexpected arguments provided.%s", VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }
    }
    else
    {
        if ( argv[0] == NULL && argv[1] == NULL )
        {
            // This is the case when user has issued 'aaa author commands default'
            vty_out (vty, "%% Command incomplete.%s", VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }
        else if (argv[0] != NULL && VTYSH_STR_EQ(argv[0], SYSTEM_AAA_NONE))
        {
            if (argv[1] != NULL)
            {
               // This is the case when user has issued 'aaa author commands default none group g1 g2'
               // if there are additional args ie argc > 1 then throw error
               vty_out (vty, "%% Misconfiguration detected.%s", VTY_NEWLINE);
               return CMD_ERR_NOTHING_TODO;
            }
            // This is the case when user has issued 'aaa author commands default none'
            group_count = 1;
            group_list = malloc(sizeof(char *));
            if (!group_list)
            {
                VLOG_ERR("Malloc failed.");
                return CMD_ERR_NOTHING_TODO;
            }
            memcpy(group_list, argv, sizeof(char *));
        }
        else
        {
            // This is the case when user has issued 'aaa author commands default group g1 g2 none'
            group_count = argc - grp_keyword_index;/* we need only the group count without group keyword */
            group_list = malloc(sizeof(char *) * group_count);
            if (!group_list)
            {
                VLOG_ERR("Malloc failed.");
                return CMD_ERR_NOTHING_TODO;
            }
            memcpy(group_list, argv + grp_keyword_index, sizeof(char *) * group_count);
        }

        /* set parameters for the structure */
        group_prio_params.no_form = false;
        group_prio_params.group_count = group_count;
        group_prio_params.group_list = group_list;
    }

    group_prio_params.aaa_method = authorization;
    group_prio_params.login_type = AAA_SERVER_GROUP_PRIO_SESSION_TYPE_DEFAULT;

    rv = configure_aaa_server_group_priority(&group_prio_params);
    free(group_list);
    return rv;
}

DEFUN_NO_FORM(cli_aaa_set_authorization,
              aaa_set_authorization_cmd,
              "aaa authorization commands default",
              AAA_STR
              AAA_USER_AUTHOR_STR
              AAA_COMMAND_AUTHOR_STR
              AAA_DEFAULT_AUTHOR_LINE_HELP_STR);

static int
show_privilege_level()
{
    struct passwd *pw;
    pw = getpwuid( getuid());
    char *priv_lvl = NULL;
    gid_t    *groups = NULL;
    int      ngroups = MAX_GROUPS_USED;
    struct   group *g;
    int itr = 0;
    int result = 0;

    priv_lvl = getenv(PRIV_LVL_ENV);

    if (priv_lvl)
    {
        vty_out(vty,"Privilege level is %s.\n", priv_lvl);
        return CMD_SUCCESS;
    }
    else
    {
        groups = (gid_t *) malloc(MAX_GROUPS_USED * sizeof(gid_t));
        if (!groups)
        {
            VLOG_ERR("Malloc failed.");
            return CMD_ERR_NOTHING_TODO;
        }
        result = getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups);
        if (result < 0)
        {
            vty_out(vty,"Failed to retrieve the privilege level.\n");
            VLOG_DBG("Retrieving group list failed.");
            free(groups);
            return CMD_ERR_NOTHING_TODO;
        }
        for (itr = 0; itr < ngroups; itr++)
        {
            g = getgrgid(groups[itr]);
            if (strncmp(g->gr_name, ROLE_ADMIN, MAX_ROLE_NAME_LEN) == 0)
            {
                vty_out(vty,"Privilege level is %s.\n", PRIV_LVL_ADMIN);
                free(groups);
                return CMD_SUCCESS;
            }
            else if (strncmp(g->gr_name, ROLE_NETOP, MAX_ROLE_NAME_LEN) == 0)
            {
                vty_out(vty,"Privilege level is %s.\n", PRIV_LVL_NETOP);
                free(groups);
                return CMD_SUCCESS;
            }
        }
        vty_out(vty,"Failed to retrieve the privilege level.\n");
        VLOG_DBG("User did not match to any of the user-groups on the switch.");
        free(groups);
        return CMD_ERR_NOTHING_TODO;
    }
}

DEFUN(cli_show_privilege_level,
      show_privilege_level_cmd,
      "show privilege-level",
      SHOW_STR
      SHOW_PRIV_LVL_STR)
{
    return show_privilege_level();
}

static int
show_aaa_radius_server_groups(const char* group_type)
{
    const struct ovsrec_aaa_server_group *group_row = NULL;
    const struct ovsrec_radius_server *server_row = NULL;
    struct shash sorted_radius_servers;
    const struct shash_node **nodes;
    int count = 0;
    int idx = 0;
    bool by_default_priority = false;
    char row_separator[AAA_TABLE_WIDTH + 1] = {};

    if (!ovsrec_aaa_server_group_first(idl))
    {
        return CMD_SUCCESS;
    }

    shash_init(&sorted_radius_servers);

    OVSREC_RADIUS_SERVER_FOR_EACH(server_row, idl)
    {
        shash_add(&sorted_radius_servers, server_row->address, (void *)server_row);
    }

    nodes = sort_servers(&sorted_radius_servers, by_default_priority, false);
    count = shash_count(&sorted_radius_servers);

    group_row = ovsrec_aaa_server_group_first(idl);
    if (group_row == NULL) {
        vty_out(vty, "No AAA Server Group configured%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    /* Create row seperator string*/
    for(idx = 0; idx < AAA_TABLE_WIDTH; idx++)
        row_separator[idx] = '-';
    row_separator[AAA_TABLE_WIDTH] = '\0';

    vty_out(vty, "%s******* AAA Mechanism RADIUS *******%s", VTY_NEWLINE, VTY_NEWLINE);

    vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
    vty_out(vty, "%-32s| %-45s| %-5s| %-8s%s","GROUP NAME", "SERVER NAME",
            "PORT", "PRIORITY", VTY_NEWLINE);
    vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);

    OVSREC_AAA_SERVER_GROUP_FOR_EACH(group_row, idl)
    {
        bool empty_group = true;
        if (!VTYSH_STR_EQ(group_row->group_type, SYSTEM_AAA_RADIUS))
        {
            continue;
        }

        if (VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_TACACS_PLUS)
                || VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_RADIUS)
                || VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_LOCAL)
                || VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_NONE))
        {
            continue;
        }

        for(idx = 0; idx < count; idx++)
        {
            server_row = (const struct ovsrec_radius_server *)nodes[idx]->data;
            if (server_row->n_group > 1 && (server_row->group[0] == group_row
                    || server_row->group[1] == group_row))
            {
                empty_group = false;
                vty_out(vty, "%-32s| %-45s| %-5"PRId64"| %-"PRId64"%s", group_row->group_name,
                        server_row->address, *(server_row->udp_port),
                        *(server_row->user_group_priority), VTY_NEWLINE);
            }
        }
        if (!empty_group)
        {
            vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
        }
    }

    by_default_priority = true;
    free(nodes);
    nodes = NULL;
    nodes = sort_servers(&sorted_radius_servers, by_default_priority, false);

    /* print radius default group rows */
    if ((group_type && VTYSH_STR_EQ(group_type, SYSTEM_AAA_RADIUS))
            || !group_type)
    {
        const struct ovsrec_aaa_server_group *default_group = NULL;
        default_group = get_row_by_server_group_name(SYSTEM_AAA_RADIUS);
        bool empty_group = true;

        for(idx = 0; idx < count; idx++)
        {
            server_row = (const struct ovsrec_radius_server *)nodes[idx]->data;
            empty_group = false;
            vty_out(vty, "%-11s %-20s| %-45s| %-5"PRId64"| %-8"PRId64"%s", default_group->group_name,
                        "(default)",
                        server_row->address, *(server_row->udp_port),
                        server_row->default_group_priority, VTY_NEWLINE);
        }
        if (!empty_group)
        {
            vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
        }
    }
    shash_destroy(&sorted_radius_servers);
    free(nodes);
    return CMD_SUCCESS;
}

static int
show_aaa_tacacs_server_groups(const char* group_type)
{
    const struct ovsrec_aaa_server_group *group_row = NULL;
    const struct ovsrec_tacacs_server *server_row = NULL;
    struct shash sorted_tacacs_servers;
    const struct shash_node **nodes;
    int count = 0;
    int idx = 0;
    bool by_default_priority = false;
    char row_separator[AAA_TABLE_WIDTH + 1] = {};

    if (!ovsrec_aaa_server_group_first(idl))
    {
        return CMD_SUCCESS;
    }

    shash_init(&sorted_tacacs_servers);

    OVSREC_TACACS_SERVER_FOR_EACH(server_row, idl)
    {
        shash_add(&sorted_tacacs_servers, server_row->address, (void *)server_row);
    }

    nodes = sort_servers(&sorted_tacacs_servers, by_default_priority, true);
    count = shash_count(&sorted_tacacs_servers);

    group_row = ovsrec_aaa_server_group_first(idl);
    if (group_row == NULL) {
        vty_out(vty, "No AAA Server Group configured%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    /* Create row seperator string*/
    for(idx = 0; idx < AAA_TABLE_WIDTH; idx++)
        row_separator[idx] = '-';
    row_separator[AAA_TABLE_WIDTH] = '\0';

    vty_out(vty, "%s******* AAA Mechanism TACACS+ *******%s", VTY_NEWLINE, VTY_NEWLINE);

    vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
    vty_out(vty, "%-32s| %-45s| %-5s| %-8s%s","GROUP NAME", "SERVER NAME",
            "PORT", "PRIORITY", VTY_NEWLINE);
    vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);

    OVSREC_AAA_SERVER_GROUP_FOR_EACH(group_row, idl)
    {
        bool empty_group = true;
        if (!VTYSH_STR_EQ(group_row->group_type, SYSTEM_AAA_TACACS_PLUS))
        {
            continue;
        }

        if (VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_TACACS_PLUS)
                || VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_RADIUS)
                || VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_LOCAL)
                || VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_NONE))
        {
            continue;
        }

        for(idx = 0; idx < count; idx++)
        {
            server_row = (const struct ovsrec_tacacs_server *)nodes[idx]->data;
            if (server_row->n_group > 1
                    && (server_row->group[0] == group_row || server_row->group[1] == group_row))
            {
                empty_group = false;
                vty_out(vty, "%-32s| %-45s| %-5"PRId64"| %-"PRId64"%s", group_row->group_name,
                        server_row->address, *(server_row->tcp_port),
                        *(server_row->user_group_priority), VTY_NEWLINE);
            }
        }
        if (!empty_group)
        {
            vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
        }
    }

    by_default_priority = true;
    free(nodes);
    nodes = NULL;
    nodes = sort_servers(&sorted_tacacs_servers, by_default_priority, true);

    /* print tacacs+ default group rows */
    if ((group_type && VTYSH_STR_EQ(group_type, SYSTEM_AAA_TACACS_PLUS))
            || !group_type)
    {
        const struct ovsrec_aaa_server_group *default_group = NULL;
        default_group = get_row_by_server_group_name(SYSTEM_AAA_TACACS_PLUS);
        bool empty_group = true;

        for(idx = 0; idx < count; idx++)
        {
            server_row = (const struct ovsrec_tacacs_server *)nodes[idx]->data;
            empty_group = false;
            vty_out(vty, "%-11s %-20s| %-45s| %-5"PRId64"| %-8"PRId64"%s", default_group->group_name,
                        "(default)", server_row->address, *(server_row->tcp_port),
                        server_row->default_group_priority, VTY_NEWLINE);
        }
        if (!empty_group)
        {
            vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
        }
    }
    shash_destroy(&sorted_tacacs_servers);
    free(nodes);
    return CMD_SUCCESS;
}


DEFUN(cli_show_aaa_server_groups,
      show_aaa_server_groups_cmd,
      "show aaa server-groups (radius | tacacs_plus)",
      SHOW_STR
      AAA_STR
      AAA_GROUP_HELP_STR
      RADIUS_HELP_STR
      TACACS_HELP_STR)
{
    if (argv[0] && VTYSH_STR_EQ(argv[0], SYSTEM_AAA_RADIUS))
        return show_aaa_radius_server_groups(SYSTEM_AAA_RADIUS);

    return show_aaa_tacacs_server_groups(SYSTEM_AAA_TACACS_PLUS);
}

DEFUN(cli_show_aaa_all_server_groups,
      show_aaa_all_server_groups_cmd,
      "show aaa server-groups",
      SHOW_STR
      AAA_STR
      AAA_GROUP_HELP_STR)
{
    int retVal = show_aaa_tacacs_server_groups(SYSTEM_AAA_TACACS_PLUS);
    if (retVal != CMD_SUCCESS) {
        return retVal;
    }

    retVal  = show_aaa_radius_server_groups(SYSTEM_AAA_RADIUS);
    if (retVal != CMD_SUCCESS) {
        return retVal;
    }

    return CMD_SUCCESS;
}


const int
aaa_server_group_sanitize_parameters(aaa_server_group_params_t *server_group_params)
{
   /* validate server group name*/
   if (strlen(server_group_params->group_name) > MAX_CHARS_IN_SERVER_GROUP_NAME)
   {
        vty_out(vty, "Server group name should be less than %d characters%s",
                MAX_CHARS_IN_SERVER_GROUP_NAME, VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
   }

   if ((VTYSH_STR_EQ(server_group_params->group_type, SYSTEM_AAA_RADIUS)) &&
       (VTYSH_STR_EQ(server_group_params->group_type, SYSTEM_AAA_TACACS_PLUS)))
   {
        vty_out(vty, "Invalid server group type%s", VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
   }

   return CMD_SUCCESS;
}

/* Create/remove RADIUS or TACACS+ server-groups */
static int
configure_aaa_server_group(aaa_server_group_params_t *server_group_params)
{
    const struct ovsrec_aaa_server_group *row = NULL;
    struct ovsdb_idl_txn *server_group_txn = NULL;
    int64_t group_prio = RADIUS_SERVER_GROUP_PRIORITY_DEFAULT;

    int retVal = aaa_server_group_sanitize_parameters(server_group_params);
    if (retVal != CMD_SUCCESS)
    {
        return retVal;
    }

    /* Start of transaction */
    START_DB_TXN(server_group_txn);

    /* See if specified AAA server group already exists */
    row = get_row_by_server_group_name(server_group_params->group_name);
    if (row == NULL)
    {
        if (server_group_params->no_form)
        {
            /* aaa server group does not exist */
            vty_out(vty, "AAA server group %s does not exist%s",
                         server_group_params->group_name, VTY_NEWLINE);
        }
        else
        {
            bool is_static_group = AAA_SERVER_GROUP_IS_STATIC_DEFAULT;
            row = ovsrec_aaa_server_group_insert(server_group_txn);
            if (row == NULL)
            {
                VLOG_ERR("Could not insert a row into AAA Server Group Table\n");
                ERRONEOUS_DB_TXN(server_group_txn,
                         "Could not insert a row into AAA Server Group Table");
            }

            VLOG_DBG("SUCCESS: Inserted a row into AAA Server Group Table\n");
            ovsrec_aaa_server_group_set_group_name(row, server_group_params->group_name);
            ovsrec_aaa_server_group_set_group_type(row, server_group_params->group_type);
            ovsrec_aaa_server_group_set_is_static(row, is_static_group);
        }
    }
    else
    {
        if (row->is_static)
        {
            ERRONEOUS_DB_TXN(server_group_txn, "Could not modify default server group!");
        }
        else if (server_group_params->no_form)
        {
            const struct ovsrec_aaa_server_group *default_group = NULL;
            const struct ovsrec_aaa_server_group_prio *group_prio_list = NULL;
            struct ovsrec_aaa_server_group **group_list = NULL;
            const char* group_name = row->group_type;
            default_group = get_row_by_server_group_name(group_name);

            group_list = malloc(sizeof(*default_group) * GROUP_COUNT_FOR_EACH_SERVER);
            if (!group_list)
            {
                ERRONEOUS_DB_TXN(server_group_txn, "Malloc failed.");
            }
            VLOG_DBG("Moving servers from server group %s to default", row->group_name);

            if (VTYSH_STR_EQ(server_group_params->group_type, SYSTEM_AAA_TACACS_PLUS))
            {
                const struct ovsrec_tacacs_server *row_iter = NULL;

                OVSREC_TACACS_SERVER_FOR_EACH(row_iter, idl) {
                    if (row_iter->n_group > 1 && (row == row_iter->group[0]
                                || row == row_iter->group[1]))
                    {
                        ovsrec_tacacs_server_set_user_group_priority(row_iter, &group_prio, 1);
                        group_list[0] = (struct ovsrec_aaa_server_group *) default_group;
                        ovsrec_tacacs_server_set_group(row_iter, group_list, GROUP_COUNT_FOR_EACH_SERVER - 1);
                    }
                }
            }
            else
            {
                const struct ovsrec_radius_server *row_iter = NULL;

                OVSREC_RADIUS_SERVER_FOR_EACH(row_iter, idl) {
                    if (row_iter->n_group > 1 && (row == row_iter->group[0]
                                || row == row_iter->group[1]))
                    {
                        ovsrec_radius_server_set_user_group_priority(row_iter, &group_prio, 1);
                        group_list[0] = (struct ovsrec_aaa_server_group *) default_group;
                        ovsrec_radius_server_set_group(row_iter, group_list, GROUP_COUNT_FOR_EACH_SERVER - 1);
                    }
                }
            }

            free(group_list);

            /* Update aaa_server_group_prio list*/
            group_prio_list = ovsrec_aaa_server_group_prio_first(idl);
            if (group_prio_list == NULL)
            {
                ERRONEOUS_DB_TXN(server_group_txn,
                                  "Could not access 'default' entry of AAA_Server_Group_Prio Table");
            }
            else if (group_prio_list->n_authentication_group_prios > 1)
            {
                int iter = 0;
                int skip = 0;
                int list_count = group_prio_list->n_authentication_group_prios;
                int64_t *key_list = malloc(sizeof(int64_t) * list_count);
                struct ovsrec_aaa_server_group **value_list =
                                      malloc(sizeof(*row) * list_count);
                if (!key_list || !(*value_list))
                {
                    if (key_list) free(key_list);
                    if (*value_list) free(*value_list);
                    ERRONEOUS_DB_TXN(server_group_txn, "Malloc failed.");
                }
                for (iter = 0; iter < list_count; iter++)
                {
                   if (row == group_prio_list->value_authentication_group_prios[iter])
                   {
                       skip = 1;
                       continue;
                   }
                   if (skip)
                   {
                       key_list[iter - skip] =
                           group_prio_list->key_authentication_group_prios[iter] - 1;
                       value_list[iter - skip] =
                           group_prio_list->value_authentication_group_prios[iter];
                   }
                   else
                   {
                       key_list[iter] = group_prio_list->key_authentication_group_prios[iter];
                       value_list[iter] = group_prio_list->value_authentication_group_prios[iter];
                   }
                }

                ovsrec_aaa_server_group_prio_set_authentication_group_prios(group_prio_list,
                                                                            key_list, value_list,
                                                                            list_count - 1);
                free(key_list);
                free(value_list);
            }

            VLOG_DBG("Deleting server group %s from AAA Server Group table", row->group_name);
            ovsrec_aaa_server_group_delete(row);
        }
    }
    /* End of transaction. */
    END_DB_TXN(server_group_txn);
}

/* CLI to create AAA TACACS+ server group  */
DEFUN (cli_aaa_create_tacacs_server_group,
       aaa_create_tacacs_server_group_cmd,
       "aaa group server (radius | tacacs_plus) WORD",
       AAA_STR
       AAA_GROUP_HELP_STR
       AAA_SERVER_TYPE_HELP_STR
       RADIUS_HELP_STR
       TACACS_HELP_STR
       AAA_GROUP_NAME_HELP_STR)
{
    int result = CMD_SUCCESS;
    char *group_type = NULL;
    static char group_name[MAX_CHARS_IN_SERVER_GROUP_NAME];
    aaa_server_group_params_t aaa_server_group_params;

    if (VTYSH_STR_EQ(SYSTEM_AAA_RADIUS , argv[0]))
    {
        group_type = SYSTEM_AAA_RADIUS;
    }
    else
    {
        group_type = SYSTEM_AAA_TACACS_PLUS;
    }

    aaa_server_group_params.group_type = group_type;
    aaa_server_group_params.group_name = (char *)argv[1];
    aaa_server_group_params.no_form = false;

    if (vty_flags & CMD_FLAG_NO_CMD)
    {
        aaa_server_group_params.no_form = true;
    }
    result =  configure_aaa_server_group(&aaa_server_group_params);
    if (result != CMD_SUCCESS)
        return result;
    if (!aaa_server_group_params.no_form)
    {
        vty->node = AAA_SERVER_GROUP_NODE;
        strncpy(group_name, argv[1], MAX_CHARS_IN_SERVER_GROUP_NAME);
        vty->index = (uintptr_t)group_name;
    }
   return CMD_SUCCESS;
}

DEFUN_NO_FORM (cli_aaa_create_tacacs_server_group,
               aaa_create_tacacs_server_group_cmd,
               "aaa group server (radius | tacacs_plus) WORD",
               AAA_STR
               AAA_GROUP_HELP_STR
               AAA_SERVER_TYPE_HELP_STR
               RADIUS_HELP_STR
               TACACS_HELP_STR
               AAA_GROUP_NAME_HELP_STR);

static const struct ovsrec_tacacs_server*
get_tacacs_server_by_name_port(const char *server_name, int64_t auth_port)
{
    const struct ovsrec_tacacs_server *row = NULL;
    OVSREC_TACACS_SERVER_FOR_EACH(row, idl) {
        if (VTYSH_STR_EQ(row->address, server_name)
            && (*(row->tcp_port) == auth_port)) {
            return row;
        }
    }
    return NULL;
}

static const struct ovsrec_radius_server*
get_radius_server_by_name_port(const char *server_name, int64_t auth_port)
{
    const struct ovsrec_radius_server *row = NULL;
    OVSREC_RADIUS_SERVER_FOR_EACH(row, idl) {
        if (VTYSH_STR_EQ(row->address, server_name)
            && (*(row->udp_port) == auth_port)) {
            return row;
        }
    }
    return NULL;
}

static int
configure_aaa_server_group_add_server(aaa_server_group_params_t *server_group_params,
                                      char* server_name, int64_t port)
{
    const struct ovsrec_aaa_server_group *group_row = NULL;
    struct ovsdb_idl_txn* status_txn = NULL;
    int64_t group_prio = RADIUS_SERVER_GROUP_PRIORITY_DEFAULT;
    struct ovsrec_aaa_server_group **group_list = NULL;

    START_DB_TXN(status_txn);

    /* See if specified AAA server group already exists */
    group_row = get_row_by_server_group_name(server_group_params->group_name);
    if (group_row == NULL)
    {
        /* aaa server group does not exist */
        ERRONEOUS_DB_TXN(status_txn, "AAA server group does not exist!");
    }

    if (VTYSH_STR_EQ(group_row->group_type, SYSTEM_AAA_RADIUS))
    {
        const struct ovsrec_radius_server *server_row = NULL;
        const struct ovsrec_aaa_server_group *default_group = NULL;
        const char *radius_group = SYSTEM_AAA_RADIUS;
        default_group = get_row_by_server_group_name(radius_group);

        group_list = malloc(sizeof(*default_group) * GROUP_COUNT_FOR_EACH_SERVER);
        if (!group_list)
        {
            ERRONEOUS_DB_TXN(status_txn, "Malloc failed.");
        }

        /* No port mentioned while adding command */
        if (port == -1)
        {
            port = RADIUS_SERVER_DEFAULT_PORT;
        }

        /* See if specified RADIUS server exist */
        server_row = get_radius_server_by_name_port(server_name, port);
        if (server_row == NULL)
        {
           /* Server does not exist*/
           ERRONEOUS_DB_TXN(status_txn, "RADIUS server does not exist!");
        }

        /* Remove server from group */
        if (server_group_params->no_form)
        {
            ovsrec_radius_server_set_user_group_priority(server_row, &group_prio, 1);

            group_list[0] = (struct ovsrec_aaa_server_group *) default_group;
            ovsrec_radius_server_set_group(server_row, group_list, GROUP_COUNT_FOR_EACH_SERVER - 1);
        }
        /* Add server to group */
        else
        {
            /* User not allowed to directly move server from user defined group*/
            if (server_row->n_group > 1)
            {
               ERRONEOUS_DB_TXN(status_txn, "RADIUS server already assigned to a group!");
            }
            else
            {
                const struct ovsrec_radius_server *row_iter = NULL;
                int64_t group_priority = 0;
                OVSREC_RADIUS_SERVER_FOR_EACH(row_iter, idl) {
                    /* get the new group maximum priority */
                    if ((row_iter->n_group > 1)
                           &&  (group_row == row_iter->group[0] || group_row == row_iter->group[1])
                           &&  (group_priority < *(row_iter->user_group_priority)))
                    {
                        group_priority = *(row_iter->user_group_priority);
                    }
                }
                ++group_priority;
                ovsrec_radius_server_set_user_group_priority(server_row, &group_priority, 1);

                group_list[0] = (struct ovsrec_aaa_server_group *) default_group;
                group_list[1] = (struct ovsrec_aaa_server_group *) group_row;
                ovsrec_radius_server_set_group(server_row, group_list, GROUP_COUNT_FOR_EACH_SERVER);
            }
        }
    }
    else if (VTYSH_STR_EQ(group_row->group_type, SYSTEM_AAA_TACACS_PLUS))
    {
        const struct ovsrec_tacacs_server *server_row = NULL;
        const struct ovsrec_aaa_server_group *default_group = NULL;
        const char *tacacs_group = SYSTEM_AAA_TACACS_PLUS;
        default_group = get_row_by_server_group_name(tacacs_group);

        group_list = malloc(sizeof(*default_group) * GROUP_COUNT_FOR_EACH_SERVER);
        if (!group_list)
        {
            ERRONEOUS_DB_TXN(status_txn, "Malloc failed.");
        }

        /* No port mentioned while adding command */
        if (port == -1)
        {
            port = TACACS_SERVER_TCP_PORT_DEFAULT;
        }

        /* See if specified TACACS+ server exist */
        server_row = get_tacacs_server_by_name_port(server_name, port);
        if (server_row == NULL)
        {
           /* Server does not exist*/
           ERRONEOUS_DB_TXN(status_txn, "TACACS+ server does not exist!");
        }

        /* Remove server from group */
        if (server_group_params->no_form)
        {
            ovsrec_tacacs_server_set_user_group_priority(server_row, &group_prio, 1);
            group_list[0] = (struct ovsrec_aaa_server_group *) default_group;
            ovsrec_tacacs_server_set_group(server_row, group_list, GROUP_COUNT_FOR_EACH_SERVER - 1);
        }
        /* Add server to group */
        else
        {
            /* User not allowed to directly move server from user defined group*/
            if (server_row->n_group > 1)
            {
               ERRONEOUS_DB_TXN(status_txn, "TACACS+ server already assigned to a group!");
            }
            else
            {
                const struct ovsrec_tacacs_server *row_iter = NULL;
                int64_t group_priority = 0;
                OVSREC_TACACS_SERVER_FOR_EACH(row_iter, idl) {
                    /* get the new group maximum priority */
                    if ((row_iter->n_group > 1)
                         &&  (group_row == row_iter->group[0] || group_row == row_iter->group[1])
                         && (group_priority < *(row_iter->user_group_priority)))
                    {
                        group_priority = *(row_iter->user_group_priority);
                    }
                }
                ++group_priority;
                ovsrec_tacacs_server_set_user_group_priority(server_row, &group_priority, 1);

                group_list[0] = (struct ovsrec_aaa_server_group *) default_group;
                group_list[1] = (struct ovsrec_aaa_server_group *) group_row;
                ovsrec_tacacs_server_set_group(server_row, group_list, GROUP_COUNT_FOR_EACH_SERVER);
            }
        }
    }

    free(group_list);
    /* End of transaction. */
    END_DB_TXN(status_txn);
}

/* CLI to add/remove AAA server to server group  */
DEFUN (aaa_group_add_server,
       aaa_group_add_server_cmd,
       "server WORD {port <1-65535>}",
       AAA_SERVER_HELP_STR
       AAA_SERVER_NAME_HELP_STR
       AUTH_PORT_HELP_STR
       AUTH_PORT_RANGE_HELP_STR)
{
    char *server_name = (char *)argv[0];
    int64_t port = -1;
    aaa_server_group_params_t aaa_server_group_params;
    aaa_server_group_params.group_name = (char *)((uintptr_t)vty->index);
    aaa_server_group_params.no_form = false;

    if ((argc == 2) && argv[1])
    {
        port = atoi(argv[1]);
    }

    if (vty_flags & CMD_FLAG_NO_CMD)
    {
        aaa_server_group_params.no_form = true;
    }
    return configure_aaa_server_group_add_server(&aaa_server_group_params, server_name, port);
}

DEFUN_NO_FORM (aaa_group_add_server,
               aaa_group_add_server_cmd,
               "server WORD {port <1-65535>}",
               AAA_SERVER_HELP_STR
               AAA_SERVER_NAME_HELP_STR
               AUTH_PORT_HELP_STR
               AUTH_PORT_RANGE_HELP_STR);

/* Specifies the TACACS+ or RADIUS server global configuration*/
/*
 * Modify TACACS+ or RADIUS server global auth-type
 * default 'auth-type' is 'pap'
 */
static int
set_global_auth_type(const char *auth_type, const bool is_tacacs_server)
{
    const struct ovsrec_system *ovs_system = NULL;
    struct ovsdb_idl_txn *status_txn = NULL;
    struct smap smap_aaa;

    /* Start of transaction */
    START_DB_TXN(status_txn);

    ovs_system = ovsrec_system_first(idl);

    if (ovs_system == NULL)
    {
        ERRONEOUS_DB_TXN(status_txn, "Could not access the System Table");
    }

    smap_clone(&smap_aaa, &ovs_system->aaa);

    smap_replace(&smap_aaa, is_tacacs_server ? SYSTEM_AAA_TACACS_AUTH : SYSTEM_AAA_RADIUS_AUTH, auth_type);

    ovsrec_system_set_aaa(ovs_system, &smap_aaa);

    smap_destroy(&smap_aaa);

    /* End of transaction */
    END_DB_TXN(status_txn);
}


/*
 * CLI to configure the shared secret key between the TACACS+ client
 * and the TACACS+ server, default value is 'testing123-1'
 */
DEFUN(cli_tacacs_server_set_auth_type,
      tacacs_server_set_auth_type_cmd,
      "tacacs-server auth-type ( pap | chap)",
      TACACS_SERVER_HELP_STR
      AAA_AUTH_TYPE_HELP_STR
      AUTH_TYPE_PAP_HELP_STR
      AUTH_TYPE_CHAP_HELP_STR)
{
    if (vty_flags & CMD_FLAG_NO_CMD)
        return set_global_auth_type(TACACS_SERVER_AUTH_TYPE_DEFAULT, true);

    return set_global_auth_type(argv[0], true);
}

DEFUN_NO_FORM(cli_tacacs_server_set_auth_type,
              tacacs_server_set_auth_type_cmd,
              "tacacs-server auth-type",
              TACACS_SERVER_HELP_STR
              AAA_AUTH_TYPE_HELP_STR);

/*
 * Modify TACACS+ or RADIUS server global passkey
 * default 'passkey' is 'testing123-1'
 */
static int
set_global_passkey(const char *passkey, const bool is_tacacs_server)
{
    const struct ovsrec_system *ovs_system = NULL;
    struct ovsdb_idl_txn *status_txn = NULL;
    struct smap smap_aaa;

    /* validate the length of passkey */
    if (strlen(passkey) > MAX_LENGTH_PASSKEY)
    {
        vty_out(vty, "Length of passkey should be less than %d%s", MAX_LENGTH_PASSKEY, VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Start of transaction */
    START_DB_TXN(status_txn);

    ovs_system = ovsrec_system_first(idl);

    if (ovs_system == NULL)
    {
        ERRONEOUS_DB_TXN(status_txn, "Could not access the System Table");
    }

    smap_clone(&smap_aaa, &ovs_system->aaa);

    smap_replace(&smap_aaa, is_tacacs_server ? SYSTEM_AAA_TACACS_PASSKEY : SYSTEM_AAA_RADIUS_PASSKEY, passkey);

    ovsrec_system_set_aaa(ovs_system, &smap_aaa);

    smap_destroy(&smap_aaa);

    /* End of transaction */
    END_DB_TXN(status_txn);
}

/*
 * CLI to configure the shared secret key between the TACACS+ client
 * and the TACACS+ server, default value is 'testing123-1'
 */
DEFUN(cli_tacacs_server_set_passkey,
      tacacs_server_set_passkey_cmd,
      "tacacs-server key WORD",
      TACACS_SERVER_HELP_STR
      SHARED_KEY_HELP_STR
      SHARED_KEY_VAL_HELP_STR)
{
    if (vty_flags & CMD_FLAG_NO_CMD)
        return set_global_passkey(TACACS_SERVER_PASSKEY_DEFAULT, true);

    return set_global_passkey(argv[0], true);
}

DEFUN_NO_FORM(cli_tacacs_server_set_passkey,
              tacacs_server_set_passkey_cmd,
              "tacacs-server key",
              TACACS_SERVER_HELP_STR
              SHARED_KEY_HELP_STR);

/*
 * Modify TACACS+ or RADIUS server global timeout
 * default 'timeout' is 5
 */
static int
set_global_timeout(const char *timeout, const bool is_tacacs_server)
{
    const struct ovsrec_system *ovs_system = NULL;
    struct ovsdb_idl_txn *status_txn = NULL;
    struct smap smap_aaa;

    /* Start of transaction */
    START_DB_TXN(status_txn);

    ovs_system = ovsrec_system_first(idl);

    if (ovs_system == NULL)
    {
        ERRONEOUS_DB_TXN(status_txn, "Could not access the System Table");
    }

    smap_clone(&smap_aaa, &ovs_system->aaa);


    smap_replace(&smap_aaa, is_tacacs_server ? SYSTEM_AAA_TACACS_TIMEOUT : SYSTEM_AAA_RADIUS_TIMEOUT, timeout);

    ovsrec_system_set_aaa(ovs_system, &smap_aaa);

    smap_destroy(&smap_aaa);

    /* End of transaction */
    END_DB_TXN(status_txn);
}

/*
 * CLI to configure the timeout interval that the switch waits
 * for response from the TACACS+ server before issue a timeout failure.
 * Default timeout value is 5 seconds
 */
DEFUN(cli_tacacs_server_set_timeout,
      tacacs_server_set_timeout_cmd,
      "tacacs-server timeout <1-60>",
      TACACS_SERVER_HELP_STR
      TIMEOUT_HELP_STR
      TIMEOUT_RANGE_HELP_STR)
{
    if (vty_flags & CMD_FLAG_NO_CMD)
        return set_global_timeout(TACACS_SERVER_TIMEOUT_DEFAULT_VAL, true);

    return set_global_timeout(argv[0], true);
}

DEFUN_NO_FORM(cli_tacacs_server_set_timeout,
              tacacs_server_set_timeout_cmd,
              "tacacs-server timeout",
              TACACS_SERVER_HELP_STR
              TIMEOUT_HELP_STR);

/*================================================================================================*/
/* Server name validation functions */
static const bool
server_name_has_all_digits(const char *server_name)
{
    while (*server_name) {
           if (!ispunct(*server_name) && !isdigit(*server_name)) {
               return false;
           }
           server_name++;
    }
    return true;
}

static const bool
is_valid_ipv4_address(const char *server_ipv4_address)
{
    struct sockaddr_in sa;

    int result = inet_pton(AF_INET, server_ipv4_address, &(sa.sin_addr));

    if (result <= 0)
       return false;

    /* 0.0.0.0 - 0.255.255.255 are not valid host addresses */
    if (*server_ipv4_address == '0')
       return false;

    if(!IS_VALID_IPV4(htonl(sa.sin_addr.s_addr)))
        return false;

    return true;
}

static const bool
is_valid_server_name(const char *server_name)
{
    if(!server_name) {
       return false;
    }

    if (server_name_has_all_digits(server_name)) {
        return is_valid_ipv4_address(server_name);
    }

    return true;
}

const int
server_sanitize_parameters(server_params_t *server_params)
{
    /* Check the validity of server name */
    if (!is_valid_server_name(server_params->server_name)) {
        vty_out(vty, "Invalid server name %s", VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Check the validity of passkey */
    if (server_params->shared_key != NULL) {
        if (strlen(server_params->shared_key) > MAX_LENGTH_PASSKEY) {
            vty_out(vty, "Length of passkey should be less than %d %s",
                         MAX_LENGTH_PASSKEY, VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }
    }

   return CMD_SUCCESS;
}

static void
tacacs_server_replace_parameters(const struct ovsrec_tacacs_server *row,
        server_params_t *server_params)
{
    if (server_params->timeout != NULL) {
        int64_t timeout = atoi(server_params->timeout);
        ovsrec_tacacs_server_set_timeout(row, &timeout, 1);
    }

    if (server_params->shared_key != NULL) {
        ovsrec_tacacs_server_set_passkey(row, server_params->shared_key);
    }

    if (server_params->auth_type != NULL) {
        ovsrec_tacacs_server_set_auth_type(row, server_params->auth_type);
    }
}


static void
server_fetch_parameters(server_params_t *server_params, bool is_tacacs_server)
{
    /* Fetch the System row */
    const struct ovsrec_system *ovs = ovsrec_system_first(idl);
    if (ovs == NULL)
    {
        return;
    }

    /* Fetch global config values */
    if (is_tacacs_server)
    {
        server_params->timeout = smap_get(&ovs->aaa, SYSTEM_AAA_TACACS_TIMEOUT);
        server_params->shared_key =  smap_get(&ovs->aaa, SYSTEM_AAA_TACACS_PASSKEY);
        server_params->auth_type = smap_get(&ovs->aaa, SYSTEM_AAA_TACACS_AUTH);
    }
    else
    {
        server_params->timeout = smap_get(&ovs->aaa, SYSTEM_AAA_RADIUS_TIMEOUT);
        server_params->shared_key =  smap_get(&ovs->aaa, SYSTEM_AAA_RADIUS_PASSKEY);
        server_params->auth_type = smap_get(&ovs->aaa, SYSTEM_AAA_RADIUS_AUTH);
        server_params->retries = smap_get(&ovs->aaa, SYSTEM_AAA_RADIUS_RETRIES);
    }
}

static void
tacacs_server_add_parameters(const struct ovsrec_tacacs_server *row,
                             server_params_t *server_params,
                             const struct ovsrec_aaa_server_group *group)
{
    struct ovsrec_aaa_server_group **group_list = NULL;
    group_list = malloc(sizeof(*group) * GROUP_COUNT_FOR_EACH_SERVER);
    if (!group_list)
    {
        VLOG_ERR("Malloc failed.");
        return;
    }
    group_list[0] = (struct ovsrec_aaa_server_group *) group;

    int64_t group_prio = TACACS_SERVER_GROUP_PRIORITY_DEFAULT;

    ovsrec_tacacs_server_set_address(row, server_params->server_name);
    if (server_params->timeout)
    {
        int64_t timeout = atoi(server_params->timeout);
        ovsrec_tacacs_server_set_timeout(row, &timeout, 1);
    }

    if (server_params->shared_key)
    {
        ovsrec_tacacs_server_set_passkey(row, server_params->shared_key);
    }

    if (server_params->auth_port)
    {
        int64_t port = atoi(server_params->auth_port);
        ovsrec_tacacs_server_set_tcp_port(row, &port, 1);
    }
    else
    {
        int64_t port = atoi(TACACS_SERVER_TCP_PORT_DEFAULT_STR);
        ovsrec_tacacs_server_set_tcp_port(row, &port, 1);
    }

    if (server_params->auth_type)
    {
        ovsrec_tacacs_server_set_auth_type(row, server_params->auth_type);
    }

    ovsrec_tacacs_server_set_default_group_priority(row, server_params->priority);
    ovsrec_tacacs_server_set_user_group_priority(row, &group_prio, 1);
    ovsrec_tacacs_server_set_group(row, group_list, GROUP_COUNT_FOR_EACH_SERVER - 1);
    free(group_list);
}

/* Add or remove a TACACS+ server */
static int
configure_tacacs_server_host(server_params_t *server_params)
{
    const struct ovsrec_tacacs_server *row = NULL;
    const struct ovsrec_tacacs_server **tacacs_info = NULL;
    const struct ovsrec_system *ovs = NULL;
    struct ovsdb_idl_txn *status_txn = NULL;


    int retVal = server_sanitize_parameters(server_params);
    if (retVal != CMD_SUCCESS) {
        return retVal;
    }

    /* Fetch the System row */
    ovs = ovsrec_system_first(idl);
    if (ovs == NULL) {
        ABORT_DB_TXN(status_txn, "Unable to fetch System table row");
    }

    /* Start of transaction */
    START_DB_TXN(status_txn);

    /* See if specified TACACS+ server already exists */
    if (server_params->auth_port)
        row = get_tacacs_server_by_name_port(server_params->server_name, atoi(server_params->auth_port));
    else
        row = get_tacacs_server_by_name_port(server_params->server_name, TACACS_SERVER_TCP_PORT_DEFAULT);

    if (row == NULL) {
        if (server_params->no_form) {
            /* Nothing to delete */
            vty_out(vty, "This server does not exist%s", VTY_NEWLINE);
        }
        else {
            /* Check if maximum allowed TACACS+ servers are already configured */
            if (ovs->n_tacacs_servers >= MAX_TACACS_SERVERS) {
                vty_out(vty, "Exceeded maximum TACACS+ servers support%s", VTY_NEWLINE);
                END_DB_TXN(status_txn);
            }

            row = ovsrec_tacacs_server_insert(status_txn);
            if (NULL == row) {
                VLOG_ERR("Could not insert a row into the TACACS+ Server Table\n");
                ERRONEOUS_DB_TXN(status_txn, "Could not insert a row into the TACACS Server Table");
            }
            else {
                VLOG_DBG("Inserted a row into the TACACS+ Server Table successfully\n");
                const struct ovsrec_aaa_server_group *default_group = NULL;
                const struct ovsrec_tacacs_server *row_iter = NULL;
                int64_t priority = 0;
                int iter = 0;
                default_group = get_row_by_server_group_name(SYSTEM_AAA_TACACS_PLUS);
                if (!default_group)
                {
                    VLOG_ERR("TACACS+ Default Server Group not configured!\n");
                    ERRONEOUS_DB_TXN(status_txn, "TACACS+ Default Server Group not configured!");
                }

                OVSREC_TACACS_SERVER_FOR_EACH(row_iter, idl) {
                    if (row_iter->default_group_priority >= priority)
                    {
                        priority = row_iter->default_group_priority;
                    }
                }
                ++priority;
                server_params->priority = priority;
                tacacs_server_add_parameters(row, server_params, default_group);

                /* Update System table */
                tacacs_info = malloc(sizeof *ovs->tacacs_servers * (ovs->n_tacacs_servers + 1));
                for (iter = 0; iter < ovs->n_tacacs_servers; iter++) {
                    tacacs_info[iter] = ovs->tacacs_servers[iter];
                }
                tacacs_info[ovs->n_tacacs_servers] = row;
                ovsrec_system_set_tacacs_servers(ovs,
                        (struct ovsrec_tacacs_server **) tacacs_info,
                        ovs->n_tacacs_servers + 1);
                free(tacacs_info);
            }
        }
    }
    else {
        if (server_params->no_form) {
            VLOG_DBG("Deleting a row from the Tacacs Server table\n");
            int iter = 0;
            int count = 0;

            /* Delete the server */
            ovsrec_tacacs_server_delete(row);

            /* Update System table */
            tacacs_info = malloc(sizeof *ovs->tacacs_servers * ovs->n_tacacs_servers);
            if (!tacacs_info)
            {
                ERRONEOUS_DB_TXN(status_txn, "Malloc failed.");
            }
            for (iter = 0; iter < ovs->n_tacacs_servers; iter++) {
                if (ovs->tacacs_servers[iter] != row) {
                    tacacs_info[count++] = ovs->tacacs_servers[iter];
                }
            }
            ovsrec_system_set_tacacs_servers(ovs,
                        (struct ovsrec_tacacs_server **) tacacs_info,
                        count);
            free(tacacs_info);
        } else {
            /* Update existing server */
            tacacs_server_replace_parameters(row, server_params);
        }
    }

    /* End of transaction. */
    END_DB_TXN(status_txn);
}

static void
show_global_server_config(const struct ovsrec_system *ovs, bool is_tacacs_server)
{
    const char *passkey = NULL;
    const char *auth_type = NULL;
    const char *timeout = NULL;
    const char *retries = NULL;
    const char *header = NULL;
    int64_t num_servers;

    /* Fetch global values */
    if (is_tacacs_server)  {
        header = "******* Global TACACS+ Configuration *******";
        num_servers = ovs->n_tacacs_servers;
        passkey = smap_get(&ovs->aaa, SYSTEM_AAA_TACACS_PASSKEY);
        timeout = smap_get(&ovs->aaa,  SYSTEM_AAA_TACACS_TIMEOUT);
        auth_type = smap_get(&ovs->aaa, SYSTEM_AAA_TACACS_AUTH);
    } else {
        header = "******* Global RADIUS Configuration *******";
        num_servers = ovs->n_radius_servers;
        passkey = smap_get(&ovs->aaa, SYSTEM_AAA_RADIUS_PASSKEY);
        timeout = smap_get(&ovs->aaa,  SYSTEM_AAA_RADIUS_TIMEOUT);
        auth_type = smap_get(&ovs->aaa, SYSTEM_AAA_RADIUS_AUTH);
        retries = smap_get(&ovs->aaa, SYSTEM_AAA_RADIUS_RETRIES);
    }

    /* Display values */
    vty_out(vty, "%s %s %s", header, VTY_NEWLINE, VTY_NEWLINE);
    vty_out(vty, "Shared-Secret: %s %s", passkey, VTY_NEWLINE);
    vty_out(vty, "Timeout: %s %s", timeout, VTY_NEWLINE);
    vty_out(vty, "Auth-Type: %s %s", auth_type, VTY_NEWLINE);

    if (!is_tacacs_server)
    {
        vty_out(vty, "Retries: %s %s", retries, VTY_NEWLINE);
    }

    vty_out(vty, "Number of Servers: %"PRId64" %s%s", num_servers, VTY_NEWLINE, VTY_NEWLINE);
}


static void
show_tacacs_server_entry(const struct ovsrec_tacacs_server *row, server_params_t *server_params)
{
    vty_out(vty, "%-25s: %s%s", "Server-Name", row->address, VTY_NEWLINE);
    vty_out(vty, "%-25s: %"PRId64"%s", "Auth-Port", *(row->tcp_port), VTY_NEWLINE);
    if (row->passkey)
    {
        vty_out(vty, "%-25s: %s%s", "Shared-Secret", row->passkey, VTY_NEWLINE);
    }
    else
    {
        vty_out(vty, "%-25s: %s%s", "Shared-Secret (default)", server_params->shared_key, VTY_NEWLINE);
    }

    if (row->timeout)
    {
        vty_out(vty, "%-25s: %"PRId64"%s", "Timeout", *(row->timeout), VTY_NEWLINE);
    }
    else
    {
        vty_out(vty, "%-25s: %s%s", "Timeout (default)", server_params->timeout, VTY_NEWLINE);
    }

    if (row->auth_type)
    {
        vty_out(vty, "%-25s: %s%s", "Auth-Type", row->auth_type, VTY_NEWLINE);
    }
    else
    {
        vty_out(vty, "%-25s: %s%s", "Auth-Type (default)", server_params->auth_type, VTY_NEWLINE);
    }
    if (row->n_group > 1)
    {
        int non_default_group_index = VTYSH_STR_EQ(row->group[0]->group_name, SYSTEM_AAA_TACACS_PLUS) ? 1 : 0;

        vty_out(vty, "%-25s: %s%s", "Server-Group", row->group[non_default_group_index]->group_name, VTY_NEWLINE);
        vty_out(vty, "%-25s: %"PRId64"%s", "Group-Priority", *(row->user_group_priority), VTY_NEWLINE);

    }
    else
    {        vty_out(vty, "%-25s: %s%s", "Server-Group (default)", row->group[0]->group_name, VTY_NEWLINE);
        vty_out(vty, "%-25s: %"PRId64"%s", "Default-Priority", row->default_group_priority, VTY_NEWLINE);
    }
    vty_out(vty, "%s", VTY_NEWLINE);
}

static void
show_radius_server_entry(const struct ovsrec_radius_server *row, server_params_t *server_params)
{
    vty_out(vty, "%-25s: %s%s", "Server-Name", row->address, VTY_NEWLINE);
    vty_out(vty, "%-25s: %"PRId64"%s", "Auth-Port", *(row->udp_port), VTY_NEWLINE);
    if (row->passkey)
    {
        vty_out(vty, "%-25s: %s%s", "Shared-Secret", row->passkey, VTY_NEWLINE);
    }
    else
    {
        vty_out(vty, "%-25s: %s%s", "Shared-Secret (default)", server_params->shared_key, VTY_NEWLINE);
    }

    if (row->timeout)
    {
        vty_out(vty, "%-25s: %"PRId64"%s", "Timeout", *(row->timeout), VTY_NEWLINE);
    }
    else
    {
        vty_out(vty, "%-25s: %s%s", "Timeout (default)", server_params->timeout, VTY_NEWLINE);
    }

    if (row->retries)
    {
        vty_out(vty, "%-25s: %"PRId64"%s", "Retries", *(row->retries), VTY_NEWLINE);
    }
    else
    {
        vty_out(vty, "%-25s: %s%s", "Retries (default)", server_params->retries, VTY_NEWLINE);
    }

    if (row->auth_type)
    {
        vty_out(vty, "%-25s: %s%s", "Auth-Type", row->auth_type, VTY_NEWLINE);
    }
    else
    {
        vty_out(vty, "%-25s: %s%s", "Auth-Type (default)", server_params->auth_type, VTY_NEWLINE);
    }
    if (row->n_group > 1)
    {
        int non_default_group_index = VTYSH_STR_EQ(row->group[0]->group_name, SYSTEM_AAA_RADIUS) ? 1 : 0;

        vty_out(vty, "%-25s: %s%s", "Server-Group", row->group[non_default_group_index]->group_name, VTY_NEWLINE);
        vty_out(vty, "%-25s: %"PRId64"%s", "Group-Priority", *(row->user_group_priority), VTY_NEWLINE);

    }
    else
    {        vty_out(vty, "%-25s: %s%s", "Server-Group (default)", row->group[0]->group_name, VTY_NEWLINE);
        vty_out(vty, "%-25s: %"PRId64"%s", "Default-Priority", row->default_group_priority, VTY_NEWLINE);
    }
    vty_out(vty, "%s", VTY_NEWLINE);
}


/* Display details for each TACACS+ or RADIUS server */
static void
show_detailed_server_data(const bool is_tacacs_server_flag)
{
    int count = 0;
    bool sort_by_default_priority = false;
    int idx = 0;
    const struct ovsrec_aaa_server_group *group_row = NULL;
    const struct ovsrec_tacacs_server *tacacs_row = NULL;
    const struct ovsrec_radius_server *radius_row = NULL;
    struct shash sorted_servers;
    server_params_t server_params = {};
    const struct shash_node **nodes;
    const char *header = NULL;

    if ((is_tacacs_server_flag && !ovsrec_tacacs_server_first(idl))
            || (!is_tacacs_server_flag && !ovsrec_radius_server_first(idl)))
    {
        return;
    }

    shash_init(&sorted_servers);
    if (is_tacacs_server_flag)
    {
        header = "****** TACACS+ Server Information ******";

        OVSREC_TACACS_SERVER_FOR_EACH(tacacs_row, idl)
        {
            shash_add(&sorted_servers, tacacs_row->address, (void *)tacacs_row);
        }
    }
    else
    {
        header = "****** RADIUS Server Information ******";

        OVSREC_RADIUS_SERVER_FOR_EACH(radius_row, idl)
        {
            shash_add(&sorted_servers, radius_row->address, (void *)radius_row);
        }
    }

    nodes = sort_servers(&sorted_servers, sort_by_default_priority, is_tacacs_server_flag);
    if (nodes == NULL)
    {
       shash_destroy(&sorted_servers);
       return;
    }

    count = shash_count(&sorted_servers);
    vty_out(vty, "%s%s", header, VTY_NEWLINE);

    server_fetch_parameters(&server_params, is_tacacs_server_flag);

    if (is_tacacs_server_flag)
    {
        OVSREC_AAA_SERVER_GROUP_FOR_EACH(group_row, idl)
        {
            if (VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_TACACS_PLUS)
                    || VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_RADIUS)
                    || VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_LOCAL))
            {
                continue;
            }

            for(idx = 0; idx < count; idx++)
            {
                tacacs_row = (const struct ovsrec_tacacs_server *)nodes[idx]->data;
                if (tacacs_row->n_group > 1 && (group_row == tacacs_row->group[0]
                            || group_row == tacacs_row->group[1]))
                {
                    show_tacacs_server_entry(tacacs_row, &server_params);
                }
            }
        }
    }
    else
    {
        OVSREC_AAA_SERVER_GROUP_FOR_EACH(group_row, idl)
        {
            if (VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_TACACS_PLUS)
                    || VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_RADIUS)
                    || VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_LOCAL))
            {
                continue;
            }

            for(idx = 0; idx < count; idx++)
            {
                radius_row = (const struct ovsrec_radius_server *)nodes[idx]->data;
                if (radius_row->n_group > 1 && (group_row == radius_row->group[0]
                          || group_row == radius_row->group[1] ))
                {
                    show_radius_server_entry(radius_row, &server_params);
                }
            }
        }
    }

    sort_by_default_priority = true;
    free(nodes);
    nodes = NULL;
    nodes = sort_servers(&sorted_servers, sort_by_default_priority, is_tacacs_server_flag);

    if(is_tacacs_server_flag)
    {
        for(idx = 0; idx < count; idx++)
        {
            tacacs_row = (const struct ovsrec_tacacs_server *)nodes[idx]->data;
            if(tacacs_row->n_group <= 1)
                show_tacacs_server_entry(tacacs_row, &server_params);
        }
    }
    else
    {
        for(idx = 0; idx < count; idx++)
        {
            radius_row = (const struct ovsrec_radius_server *)nodes[idx]->data;
            if(radius_row->n_group <= 1)
                show_radius_server_entry(radius_row, &server_params);
        }
    }

   shash_destroy(&sorted_servers);
   free(nodes);
}

/* Summarized details for TACACS+ or RADIUS servers */
static void
show_summarized_server_data(const bool is_tacacs_server_flag)
{
    const struct ovsrec_tacacs_server *tacacs_row = NULL;
    const struct ovsrec_radius_server *radius_row = NULL;
    char row_separator[AAA_TABLE_WIDTH + 1] = {};
    int count = 0;
    int idx = 0;
    bool sort_by_default_priority = true;
    struct shash sorted_servers;
    const struct shash_node **nodes;

    /* Create row seperator string*/
    for(idx = 0; idx < AAA_TABLE_WIDTH; idx++)
        row_separator[idx] = '-';
    row_separator[AAA_TABLE_WIDTH] = '\0';

    /* Sort tacacs or radius servers by default_priority*/
    shash_init(&sorted_servers);
    if (is_tacacs_server_flag)
    {
        OVSREC_TACACS_SERVER_FOR_EACH(tacacs_row, idl)
        {
            shash_add(&sorted_servers, tacacs_row->address, (void *)tacacs_row);
        }
    }
    else
    {
        OVSREC_RADIUS_SERVER_FOR_EACH(radius_row, idl)
        {
            shash_add(&sorted_servers, radius_row->address, (void *)radius_row);
        }
    }

    nodes = sort_servers(&sorted_servers, sort_by_default_priority, is_tacacs_server_flag);
    if (nodes == NULL)
    {
        shash_destroy(&sorted_servers);
        return;
    }

    count = shash_count(&sorted_servers);
    vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
    vty_out(vty, "%-45s | %-5s%s", "SERVER NAME", "PORT", VTY_NEWLINE);
    vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);

    if(is_tacacs_server_flag)
    {
        for(idx = 0; idx < count; idx++)
        {
            tacacs_row = (const struct ovsrec_tacacs_server *)nodes[idx]->data;
            vty_out(vty,"%-45s | %-5"PRId64"%s", tacacs_row->address, *(tacacs_row->tcp_port), VTY_NEWLINE);
        }
    }
    else
    {
        for(idx = 0; idx < count; idx++)
        {
            radius_row = (const struct ovsrec_radius_server *)nodes[idx]->data;
            vty_out(vty,"%-45s | %-5"PRId64"%s", radius_row->address, *(radius_row->udp_port), VTY_NEWLINE);
        }
    }

    shash_destroy(&sorted_servers);
    free(nodes);
}

static int
show_server_info(const bool showDetails, const bool is_tacacs_server)
{
    const struct ovsrec_system *ovs = NULL;
    const struct ovsrec_tacacs_server *tacacs_row = NULL;
    const struct ovsrec_radius_server *radius_row = NULL;

    /* Fetch the system row */
    ovs = ovsrec_system_first(idl);
    if (ovs == NULL) {
        vty_out(vty, "Command failed%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    /* display global config */
    show_global_server_config(ovs, is_tacacs_server);

    if (is_tacacs_server)
    {
        tacacs_row = ovsrec_tacacs_server_first(idl);
        if (tacacs_row == NULL)
        {
            vty_out(vty, "No TACACS+ Servers configured%s", VTY_NEWLINE);
            return CMD_SUCCESS;
        }
    }
    else
    {
        radius_row = ovsrec_radius_server_first(idl);
        if (radius_row == NULL)
        {
            vty_out(vty, "No RADIUS Servers configured%s", VTY_NEWLINE);
            return CMD_SUCCESS;
        }
    }

    if (showDetails)
    {
        show_detailed_server_data(is_tacacs_server);
    }
    else
    {
        show_summarized_server_data(is_tacacs_server);
    }

    return CMD_SUCCESS;
}

DEFUN(cli_show_tacacs_server,
        show_tacacs_server_cmd,
        "show tacacs-server {detail}",
        SHOW_STR
        SHOW_TACACS_SERVER_HELP_STR
        SHOW_DETAILS_HELP_STR)
{
    bool detail = false;

    if (argv[0] != NULL && VTYSH_STR_EQ(argv[0], "detail"))
    {
        detail = true;
    }

    return show_server_info(detail, true);
}

/* CLI to add tacacs-sever */
DEFUN (cli_tacacs_server_host,
       tacacs_server_host_cmd,
       "tacacs-server host WORD {port <1-65535> | timeout <1-60> | key WORD | auth-type (pap | chap)}",
       TACACS_SERVER_HELP_STR
       TACACS_SERVER_HOST_HELP_STR
       TACACS_SERVER_NAME_HELP_STR
       AUTH_PORT_HELP_STR
       AUTH_PORT_RANGE_HELP_STR
       TIMEOUT_HELP_STR
       TIMEOUT_RANGE_HELP_STR
       SHARED_KEY_HELP_STR
       SHARED_KEY_VAL_HELP_STR
       AAA_AUTH_TYPE_HELP_STR
       AUTH_TYPE_PAP_HELP_STR
       AUTH_TYPE_CHAP_HELP_STR)
{
    server_params_t tacacs_server_params = {0};

    if (vty_flags & CMD_FLAG_NO_CMD)
    {
        tacacs_server_params.no_form = true;
        tacacs_server_params.server_name = argv[0];
        tacacs_server_params.auth_port = argv[1];
    }
    else
    {
        tacacs_server_params.server_name = argv[0];
        tacacs_server_params.auth_port = argv[1];
        tacacs_server_params.timeout = argv[2];
        tacacs_server_params.shared_key = argv[3];
        tacacs_server_params.auth_type = argv[4];
        tacacs_server_params.no_form = false;
        tacacs_server_params.is_radius_server = false;
    }

    return configure_tacacs_server_host(&tacacs_server_params);
}

/* CLI to remove tacacs-sever */
DEFUN_NO_FORM (cli_tacacs_server_host,
       tacacs_server_host_cmd,
       "tacacs-server host WORD {port <1-65535>}",
       TACACS_SERVER_HELP_STR
       TACACS_SERVER_HOST_HELP_STR
       TACACS_SERVER_NAME_HELP_STR
       AUTH_PORT_HELP_STR
       AUTH_PORT_RANGE_HELP_STR);

/*
 * CLI to configure the timeout interval that the switch waits
 * for response from the RADIUS server before issue a timeout failure.
 * Default timeout value is 5 seconds
 */
DEFUN(cli_radius_server_set_timeout,
      radius_server_set_timeout_cmd,
      "radius-server timeout <1-60>",
      RADIUS_SERVER_HELP_STR
      TIMEOUT_HELP_STR
      TIMEOUT_RANGE_HELP_STR)
{
    if (vty_flags & CMD_FLAG_NO_CMD)
        return set_global_timeout(RADIUS_SERVER_DEFAULT_TIMEOUT_STR, false);

    return set_global_timeout(argv[0], false);
}

DEFUN_NO_FORM(cli_radius_server_set_timeout,
              radius_server_set_timeout_cmd,
              "radius-server timeout",
              RADIUS_SERVER_HELP_STR
              TIMEOUT_HELP_STR);

DEFUN(cli_radius_server_set_auth_type,
      radius_server_set_auth_type_cmd,
      "radius-server auth-type ( pap | chap)",
      RADIUS_SERVER_HELP_STR
      AAA_AUTH_TYPE_HELP_STR
      AUTH_TYPE_PAP_HELP_STR
      AUTH_TYPE_CHAP_HELP_STR)
{
    if (vty_flags & CMD_FLAG_NO_CMD)
        return set_global_auth_type(RADIUS_SERVER_AUTH_TYPE_DEFAULT, false);

    return set_global_auth_type(argv[0], false);
}

DEFUN_NO_FORM(cli_radius_server_set_auth_type,
              radius_server_set_auth_type_cmd,
              "radius-server auth-type",
              RADIUS_SERVER_HELP_STR
              AAA_AUTH_TYPE_HELP_STR);

/*
 * CLI to configure the shared secret key between the RADIUS client
 * and the RADIUS server, default value is 'testing123-1'
 */
DEFUN(cli_radius_server_set_passkey,
      radius_server_set_passkey_cmd,
      "radius-server key WORD",
      RADIUS_SERVER_HELP_STR
      SHARED_KEY_HELP_STR
      RADIUS_SHARED_KEY_VAL_HELP_STR)
{
    if (vty_flags & CMD_FLAG_NO_CMD)
        return set_global_passkey(RADIUS_SERVER_DEFAULT_PASSKEY, false);

    return set_global_passkey(argv[0], false);
}

DEFUN_NO_FORM(cli_radius_server_set_passkey,
              radius_server_set_passkey_cmd,
              "radius-server key",
              RADIUS_SERVER_HELP_STR
              SHARED_KEY_HELP_STR);

/*
 * Modify RADIUS server global retries
 * default 'retries' is 1
 */
static int
set_global_retries(const char *retries)
{
    const struct ovsrec_system *ovs_system = NULL;
    struct ovsdb_idl_txn *status_txn = NULL;
    struct smap smap_aaa;

    /* Start of transaction */
    START_DB_TXN(status_txn);

    ovs_system = ovsrec_system_first(idl);

    if (ovs_system == NULL)
    {
        ERRONEOUS_DB_TXN(status_txn, "Could not access the System Table");
    }

    smap_clone(&smap_aaa, &ovs_system->aaa);


    smap_replace(&smap_aaa, SYSTEM_AAA_RADIUS_RETRIES, retries);

    ovsrec_system_set_aaa(ovs_system, &smap_aaa);

    smap_destroy(&smap_aaa);

    /* End of transaction */
    END_DB_TXN(status_txn);
}

DEFUN(cli_radius_server_set_retries,
      radius_server_set_retries_cmd,
      "radius-server retries <0-5>",
      RADIUS_SERVER_HELP_STR
      RETRIES_HELP_STR
      RETRIES_RANGE_HELP_STR)
{
    if (vty_flags & CMD_FLAG_NO_CMD)
        return set_global_retries(RADIUS_SERVER_DEFAULT_RETRIES_STR);

    return set_global_retries(argv[0]);
}

DEFUN_NO_FORM(cli_radius_server_set_retries,
              radius_server_set_retries_cmd,
              "radius-server retries",
              RADIUS_SERVER_HELP_STR
              RETRIES_HELP_STR);

static void
radius_server_replace_parameters(const struct ovsrec_radius_server *row,
        server_params_t *server_params)
{
    if (server_params->timeout != NULL) {
        int64_t timeout = atoi(server_params->timeout);
        ovsrec_radius_server_set_timeout(row, &timeout, 1);
    }

    if (server_params->shared_key != NULL) {
        ovsrec_radius_server_set_passkey(row, server_params->shared_key);
    }

    if (server_params->auth_type != NULL) {
        ovsrec_radius_server_set_auth_type(row, server_params->auth_type);
    }

    if (server_params->retries != NULL) {
        int64_t retries = atoi(server_params->retries);
        ovsrec_radius_server_set_retries(row, &retries, 1);
    }
}

static void
radius_server_add_parameters(const struct ovsrec_radius_server *row,
                             server_params_t *server_params,
                             const struct ovsrec_aaa_server_group *group)
{
    struct ovsrec_aaa_server_group **group_list = NULL;
    group_list = malloc(sizeof(*group) * GROUP_COUNT_FOR_EACH_SERVER);
    group_list[0] = (struct ovsrec_aaa_server_group *) group;
    int64_t group_prio = RADIUS_SERVER_GROUP_PRIORITY_DEFAULT;

    ovsrec_radius_server_set_address(row, server_params->server_name);
    if (server_params->timeout)
    {
        int64_t timeout = atoi(server_params->timeout);
        ovsrec_radius_server_set_timeout(row, &timeout, 1);
    }

    if (server_params->shared_key)
    {
        ovsrec_radius_server_set_passkey(row, server_params->shared_key);
    }

    if (server_params->auth_port)
    {
        int64_t port = atoi(server_params->auth_port);
        ovsrec_radius_server_set_udp_port(row, &port, 1);
    }
    else
    {
        int64_t port = atoi(RADIUS_SERVER_DEFAULT_PORT_STR);
        ovsrec_radius_server_set_udp_port(row, &port, 1);
    }

    if (server_params->auth_type)
    {
        ovsrec_radius_server_set_auth_type(row, server_params->auth_type);
    }

    if (server_params->retries)
    {
        int64_t retries = atoi(server_params->retries);
        ovsrec_radius_server_set_retries(row, &retries, 1);
    }

    ovsrec_radius_server_set_default_group_priority(row, server_params->priority);
    ovsrec_radius_server_set_user_group_priority(row, &group_prio, 1);
    ovsrec_radius_server_set_group(row, group_list, GROUP_COUNT_FOR_EACH_SERVER - 1);

    free(group_list);
}


/* Add or remove a RADIUS server */
static int
configure_radius_server_host(server_params_t *server_params)
{
    const struct ovsrec_radius_server *row = NULL;
    const struct ovsrec_radius_server **radius_info = NULL;
    const struct ovsrec_system *ovs = NULL;
    struct ovsdb_idl_txn *status_txn = NULL;

    int retVal = server_sanitize_parameters(server_params);
    if (retVal != CMD_SUCCESS) {
        return retVal;
    }

    /* Fetch the System row */
    ovs = ovsrec_system_first(idl);
    if (ovs == NULL) {
        ABORT_DB_TXN(status_txn, "Unable to fetch System table row");
    }

    /* Start of transaction */
    START_DB_TXN(status_txn);

    /* See if specified RADIUS server already exists */
    if (server_params->auth_port)
        row = get_radius_server_by_name_port(server_params->server_name, atoi(server_params->auth_port));
    else
        row = get_radius_server_by_name_port(server_params->server_name, RADIUS_SERVER_DEFAULT_PORT);

    if (row == NULL) {
        if (server_params->no_form) {
            /* Nothing to delete */
            vty_out(vty, "This server does not exist%s", VTY_NEWLINE);
        }
        else {
            /* Check if maximum allowed RADIUS servers are already configured */
            if (ovs->n_radius_servers >= MAX_RADIUS_SERVERS) {
                vty_out(vty, "Exceeded maximum RADIUS servers support%s", VTY_NEWLINE);
                END_DB_TXN(status_txn);
            }

            row = ovsrec_radius_server_insert(status_txn);
            if (NULL == row) {
                VLOG_ERR("Could not insert a row into the RADIUS Server Table\n");
                ERRONEOUS_DB_TXN(status_txn, "Could not insert a row into the RADIUS Server Table");
            }
            else {
                VLOG_DBG("Inserted a row into the RADIUS Server Table successfully\n");
                const struct ovsrec_aaa_server_group *default_group = NULL;
                const struct ovsrec_radius_server *row_iter = NULL;
                int64_t priority = 0;
                int iter = 0;
                default_group = get_row_by_server_group_name(SYSTEM_AAA_RADIUS);
                if (!default_group)
                {
                    VLOG_ERR("RADIUS Default Server Group not configured!\n");
                    ERRONEOUS_DB_TXN(status_txn, "RADIUS Default Server Group not configured!");
                }

                OVSREC_RADIUS_SERVER_FOR_EACH(row_iter, idl) {
                    if (row_iter->default_group_priority >= priority)
                    {
                        priority = row_iter->default_group_priority;
                    }
                }
                ++priority;
                server_params->priority = priority;
                radius_server_add_parameters(row, server_params, default_group);

                /* Update System table */
                radius_info = malloc(sizeof *ovs->radius_servers * (ovs->n_radius_servers + 1));
                for (iter = 0; iter < ovs->n_radius_servers; iter++) {
                    radius_info[iter] = ovs->radius_servers[iter];
                }
                radius_info[ovs->n_radius_servers] = row;
                ovsrec_system_set_radius_servers(ovs,
                        (struct ovsrec_radius_server **) radius_info,
                        ovs->n_radius_servers + 1);
                free(radius_info);
            }
        }
    }
    else {
        if (server_params->no_form) {
            VLOG_DBG("Deleting a row from the RADIUS Server table\n");
            int iter = 0;
            int count = 0;

            /* Delete the server */
            ovsrec_radius_server_delete(row);

            /* Update System table */
            radius_info = malloc(sizeof *ovs->radius_servers * ovs->n_radius_servers);
            for (iter = 0; iter < ovs->n_radius_servers; iter++) {
                if (ovs->radius_servers[iter] != row) {
                    radius_info[count++] = ovs->radius_servers[iter];
                }
            }
            ovsrec_system_set_radius_servers(ovs,
                        (struct ovsrec_radius_server **) radius_info,
                        count);
            free(radius_info);
        } else {
            /* Update existing server */
            radius_server_replace_parameters(row, server_params);
        }
    }

    /* End of transaction. */
    END_DB_TXN(status_txn);
}


/* CLI to add radius-server */
DEFUN (cli_radius_server_host,
       radius_server_host_cmd,
       "radius-server host WORD {port <1-65535> | timeout <1-60> | key WORD | retries <1-5> | auth-type (pap | chap)}",
       RADIUS_SERVER_HELP_STR
       RADIUS_SERVER_HOST_HELP_STR
       RADIUS_SERVER_NAME_HELP_STR
       AUTH_PORT_HELP_STR
       RADIUS_AUTH_PORT_RANGE_HELP_STR
       TIMEOUT_HELP_STR
       TIMEOUT_RANGE_HELP_STR
       SHARED_KEY_HELP_STR
       RADIUS_SHARED_KEY_VAL_HELP_STR
       RETRIES_HELP_STR
       RETRIES_RANGE_HELP_STR
       AAA_AUTH_TYPE_HELP_STR
       AUTH_TYPE_PAP_HELP_STR
       AUTH_TYPE_CHAP_HELP_STR)
{
    server_params_t radius_server_params = {0};

    if (vty_flags & CMD_FLAG_NO_CMD)
    {
        radius_server_params.no_form = true;
        radius_server_params.server_name = argv[0];
        radius_server_params.auth_port = argv[1];
    }
    else
    {
        radius_server_params.server_name = argv[0];
        radius_server_params.auth_port = argv[1];
        radius_server_params.timeout = argv[2];
        radius_server_params.shared_key = argv[3];
        radius_server_params.retries = argv[4];
        radius_server_params.auth_type = argv[5];
        radius_server_params.no_form = false;
        radius_server_params.is_radius_server = true;
    }

    return configure_radius_server_host(&radius_server_params);
}

/* CLI to remove radius-server */
DEFUN_NO_FORM (cli_radius_server_host,
       radius_server_host_cmd,
       "radius-server host WORD {port <1-65535>}",
       RADIUS_SERVER_HELP_STR
       RADIUS_SERVER_HOST_HELP_STR
       RADIUS_SERVER_NAME_HELP_STR
       AUTH_PORT_HELP_STR
       AUTH_PORT_RANGE_HELP_STR);

DEFUN(cli_show_radius_server,
      show_radius_server_cmd,
      "show radius-server {detail}",
      SHOW_STR
      SHOW_RADIUS_SERVER_HELP_STR
      SHOW_DETAILS_HELP_STR)
{
    bool detail = false;

    if (argv[0] != NULL && VTYSH_STR_EQ(argv[0], "detail"))
    {
        detail = true;
    }

   return show_server_info(detail, false);
}



/* Shows auto provisioning status.*/
static int
show_auto_provisioning()
{
    const struct ovsrec_system *row = NULL;

    row = ovsrec_system_first(idl);

    if (!row)
    {
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    if (smap_get(&row->auto_provisioning_status, "performed") != NULL)
    {
        if (VTYSH_STR_EQ
                (smap_get(&row->auto_provisioning_status, "performed"), "True"))
        {
            vty_out(vty, " Performed : %s%s", "Yes", VTY_NEWLINE);
            vty_out(vty, " URL       : %s%s",
                    smap_get(&row->auto_provisioning_status, "url"),
                    VTY_NEWLINE);
        }
        else
        {
            vty_out(vty, " Performed : %s%s", "No", VTY_NEWLINE);
        }
    }

    return CMD_SUCCESS;
}

/* CLI to show auto provisioning status */
DEFUN(cli_show_auto_provisioning,
        show_auto_provisioning_cmd,
        "show autoprovisioning", SHOW_STR "Show auto provisioning status\n")
{
    return show_auto_provisioning();
}

/* Shows ssh authentication method.*/
static int
show_ssh_auth_method()
{
    const struct ovsrec_system *row = NULL;

    row = ovsrec_system_first(idl);

    if (!row)
    {
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    if (VTYSH_STR_EQ
            (smap_get(&row->aaa, SSH_PUBLICKEY_AUTHENTICATION_ENABLE),
                       SSH_AUTH_ENABLE))
    {
        vty_out(vty, " SSH publickey authentication : %s%s", "Enabled",
                VTY_NEWLINE);
    }
    else
    {
        vty_out(vty, " SSH publickey authentication : %s%s", "Disabled",
                VTY_NEWLINE);
    }

    if (VTYSH_STR_EQ
            (smap_get(&row->aaa, SSH_PASSWORD_AUTHENTICATION_ENABLE),
                       SSH_AUTH_ENABLE))
    {
        vty_out(vty, " SSH password authentication  : %s%s", "Enabled",
                VTY_NEWLINE);
    }
    else
    {
        vty_out(vty, " SSH password authentication  : %s%s", "Disabled",
                VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}

/* CLI to show authentication mechanism configured in DB */
DEFUN(cli_show_ssh_auth_method,
        show_ssh_auth_method_cmd,
        "show ssh authentication-method",
        SHOW_STR "Show SSH configuration\n" "Show authentication method\n")
{
    return show_ssh_auth_method();
}

/* Set ssh public key aythentication status.*/
static int
set_ssh_publickey_auth(const char *status)
{
    const struct ovsrec_system *row = NULL;
    enum ovsdb_idl_txn_status txn_status;
    struct ovsdb_idl_txn *status_txn = cli_do_config_start();
    struct smap smap_aaa;

    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    row = ovsrec_system_first(idl);

    if (!row)
    {
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    smap_clone(&smap_aaa, &row->aaa);

    if (VTYSH_STR_EQ(SSH_AUTH_ENABLE, status))
    {
        smap_replace(&smap_aaa, SSH_PUBLICKEY_AUTHENTICATION_ENABLE,
                      SSH_AUTH_ENABLE);
    }
    else if (VTYSH_STR_EQ(SSH_AUTH_DISABLE, status))
    {
        smap_replace(&smap_aaa, SSH_PUBLICKEY_AUTHENTICATION_ENABLE,
                      SSH_AUTH_DISABLE);
    }

    ovsrec_system_set_aaa(row, &smap_aaa);

    txn_status = cli_do_config_finish(status_txn);
    smap_destroy(&smap_aaa);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

/* CLI to enable ssh public key authentication */
DEFUN(cli_set_ssh_publickey_auth,
        set_ssh_publickey_auth_cmd,
        "ssh public-key-authentication",
        "SSH authentication\n" "Enable publickey authentication method\n")
{
    return set_ssh_publickey_auth(SSH_AUTH_ENABLE);
}

/* CLI to disable ssh public key authentication */
DEFUN(cli_no_set_ssh_publickey_auth,
        no_set_ssh_publickey_auth_cmd,
        "no ssh public-key-authentication",
        NO_STR
        "SSH authentication\n" "Enable publickey authentication method\n")
{
    return set_ssh_publickey_auth(SSH_AUTH_DISABLE);
}

/* Set ssh password authentication.*/
static int
set_ssh_password_auth(const char *status)
{
    const struct ovsrec_system *row = NULL;
    enum ovsdb_idl_txn_status txn_status;
    struct ovsdb_idl_txn *status_txn = cli_do_config_start();
    struct smap smap_aaa;

    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    row = ovsrec_system_first(idl);

    if (!row)
    {
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    smap_clone(&smap_aaa, &row->aaa);

    if (VTYSH_STR_EQ(SSH_AUTH_ENABLE, status))
    {
        smap_replace(&smap_aaa, SSH_PASSWORD_AUTHENTICATION_ENABLE,
                      SSH_AUTH_ENABLE);
    }
    else if (VTYSH_STR_EQ(SSH_AUTH_DISABLE, status))
    {
        smap_replace(&smap_aaa, SSH_PASSWORD_AUTHENTICATION_ENABLE,
                      SSH_AUTH_DISABLE);
    }

    ovsrec_system_set_aaa(row, &smap_aaa);

    txn_status = cli_do_config_finish(status_txn);
    smap_destroy(&smap_aaa);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

/* CLI to enable ssh password athentication */
DEFUN(cli_set_ssh_password_auth,
        set_ssh_password_auth_cmd,
        "ssh password-authentication",
        "SSH authentication\n" "Enable password authentication method\n")
{
    return set_ssh_password_auth(SSH_AUTH_ENABLE);
}

/* CLI to disable ssh password athentication */
DEFUN(cli_no_set_ssh_password_auth,
        no_set_ssh_password_auth_cmd,
        "no ssh password-authentication",
        NO_STR "SSH authentication\n" "Enable password authentication method\n")
{
    return set_ssh_password_auth(SSH_AUTH_DISABLE);
}

/*******************************************************************
 * @func        : aaa_ovsdb_init
 * @detail      : Add aaa related table & columns to ops-cli
 *                idl cache
 *******************************************************************/
static void
aaa_ovsdb_init(void)
{
    /* Add AAA columns. */
    ovsdb_idl_add_column(idl, &ovsrec_system_col_aaa);
    ovsdb_idl_add_table(idl, &ovsrec_table_aaa_server_group);
    ovsdb_idl_add_column(idl, &ovsrec_aaa_server_group_col_group_type);
    ovsdb_idl_add_column(idl, &ovsrec_aaa_server_group_col_group_name);
    ovsdb_idl_add_column(idl, &ovsrec_aaa_server_group_col_is_static);
    ovsdb_idl_add_table(idl, &ovsrec_table_aaa_server_group_prio);
    ovsdb_idl_add_column(idl, &ovsrec_aaa_server_group_prio_col_session_type);
    ovsdb_idl_add_column(idl, &ovsrec_aaa_server_group_prio_col_authentication_group_prios);
    ovsdb_idl_add_column(idl, &ovsrec_aaa_server_group_prio_col_authorization_group_prios);

    /* Add Auto Provision Column. */
    ovsdb_idl_add_column(idl, &ovsrec_system_col_auto_provisioning_status);

    /* Add tacacs-server columns. */
    ovsdb_idl_add_column(idl, &ovsrec_system_col_tacacs_servers);
    ovsdb_idl_add_table(idl, &ovsrec_table_tacacs_server);
    ovsdb_idl_add_column(idl, &ovsrec_tacacs_server_col_address);
    ovsdb_idl_add_column(idl, &ovsrec_tacacs_server_col_tcp_port);
    ovsdb_idl_add_column(idl, &ovsrec_tacacs_server_col_timeout);
    ovsdb_idl_add_column(idl, &ovsrec_tacacs_server_col_passkey);
    ovsdb_idl_add_column(idl, &ovsrec_tacacs_server_col_auth_type);
    ovsdb_idl_add_column(idl, &ovsrec_tacacs_server_col_default_group_priority);
    ovsdb_idl_add_column(idl, &ovsrec_tacacs_server_col_user_group_priority);
    ovsdb_idl_add_column(idl, &ovsrec_tacacs_server_col_group);

    /* Add radius-server columns. */
    ovsdb_idl_add_column(idl, &ovsrec_system_col_radius_servers);
    ovsdb_idl_add_table(idl, &ovsrec_table_radius_server);
    ovsdb_idl_add_column(idl, &ovsrec_radius_server_col_address);
    ovsdb_idl_add_column(idl, &ovsrec_radius_server_col_udp_port);
    ovsdb_idl_add_column(idl, &ovsrec_radius_server_col_timeout);
    ovsdb_idl_add_column(idl, &ovsrec_radius_server_col_passkey);
    ovsdb_idl_add_column(idl, &ovsrec_radius_server_col_retries);
    ovsdb_idl_add_column(idl, &ovsrec_radius_server_col_auth_type);
    ovsdb_idl_add_column(idl, &ovsrec_radius_server_col_default_group_priority);
    ovsdb_idl_add_column(idl, &ovsrec_radius_server_col_user_group_priority);
    ovsdb_idl_add_column(idl, &ovsrec_radius_server_col_group);

    return;
}

/* Initialize AAA related cli node.
 */
void
cli_pre_init(void)
{
    aaa_ovsdb_init();
    return;
}

/* Install  AAA related vty command elements. */
void
cli_post_init(void)
{
    vtysh_ret_val retval = e_vtysh_error;

    /* Install default VTY commands to new nodes.  */
    install_default (AAA_SERVER_GROUP_NODE);
    install_element(ENABLE_NODE, &aaa_show_aaa_authentication_cmd);
    install_element(ENABLE_NODE, &aaa_show_aaa_authorization_cmd);
    install_element(CONFIG_NODE, &aaa_set_authentication_cmd);
    install_element(CONFIG_NODE, &no_aaa_set_authentication_cmd);
    install_element(CONFIG_NODE, &aaa_set_authorization_cmd);
    install_element(CONFIG_NODE, &no_aaa_set_authorization_cmd);
    install_element(CONFIG_NODE, &aaa_allow_fail_through_cmd);
    install_element(CONFIG_NODE, &no_aaa_allow_fail_through_cmd);
    install_element(CONFIG_NODE, &aaa_create_tacacs_server_group_cmd);
    install_element(CONFIG_NODE, &no_aaa_create_tacacs_server_group_cmd);
    install_element(AAA_SERVER_GROUP_NODE, &aaa_group_add_server_cmd);
    install_element(AAA_SERVER_GROUP_NODE, &no_aaa_group_add_server_cmd);
    install_element(CONFIG_NODE, &tacacs_server_set_passkey_cmd);
    install_element(CONFIG_NODE, &tacacs_server_set_timeout_cmd);
    install_element(CONFIG_NODE, &tacacs_server_set_auth_type_cmd);
    install_element(CONFIG_NODE, &no_tacacs_server_set_passkey_cmd);
    install_element(CONFIG_NODE, &no_tacacs_server_set_timeout_cmd);
    install_element(CONFIG_NODE, &no_tacacs_server_set_auth_type_cmd);
    install_element(CONFIG_NODE, &tacacs_server_host_cmd);
    install_element(CONFIG_NODE, &no_tacacs_server_host_cmd);
    install_element(ENABLE_NODE, &show_tacacs_server_cmd);
    install_element(CONFIG_NODE, &radius_server_set_passkey_cmd);
    install_element(CONFIG_NODE, &radius_server_set_retries_cmd);
    install_element(CONFIG_NODE, &radius_server_set_timeout_cmd);
    install_element(CONFIG_NODE, &radius_server_set_auth_type_cmd);
    install_element(CONFIG_NODE, &no_radius_server_set_passkey_cmd);
    install_element(CONFIG_NODE, &no_radius_server_set_timeout_cmd);
    install_element(CONFIG_NODE, &no_radius_server_set_retries_cmd);
    install_element(CONFIG_NODE, &no_radius_server_set_auth_type_cmd);
    install_element(CONFIG_NODE, &radius_server_host_cmd);
    install_element(CONFIG_NODE, &no_radius_server_host_cmd);
    install_element(ENABLE_NODE, &show_radius_server_cmd);
    install_element(ENABLE_NODE, &show_aaa_server_groups_cmd);
    install_element(ENABLE_NODE, &show_aaa_all_server_groups_cmd);
    install_element(ENABLE_NODE, &show_auto_provisioning_cmd);
    install_element(ENABLE_NODE, &show_ssh_auth_method_cmd);
    install_element(VIEW_NODE, &show_privilege_level_cmd);
    install_element(ENABLE_NODE, &show_privilege_level_cmd);
    install_element(CONFIG_NODE, &set_ssh_publickey_auth_cmd);
    install_element(CONFIG_NODE, &no_set_ssh_publickey_auth_cmd);
    install_element(CONFIG_NODE, &set_ssh_password_auth_cmd);
    install_element(CONFIG_NODE, &no_set_ssh_password_auth_cmd);

    /* Installing running config sub-context with global config context */
    retval = install_show_run_config_subcontext(e_vtysh_config_context,
                                                e_vtysh_config_context_aaa,
                                                &vtysh_config_context_aaa_clientcallback,
                                                NULL, NULL);
    if(e_vtysh_ok != retval)
    {
        vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_ERR,
                              "config context unable to add aaa client callback");
        assert(0);
    }
    return;
}

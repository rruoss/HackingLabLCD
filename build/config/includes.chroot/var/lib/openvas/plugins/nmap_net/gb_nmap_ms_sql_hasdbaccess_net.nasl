###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_ms_sql_hasdbaccess_net.nasl 10 2013-10-27 10:03:59Z jan $
#
# Autogenerated NSE wrapper
#
# Authors:
# NSE-Script: Patrik Karlsson
# NASL-Wrapper: autogenerated
#
# Copyright:
# NSE-Script: The Nmap Security Scanner (http://nmap.org)
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Queries Microsoft SQL Server (ms-sql) for a list of databases a user has access to.

The script needs an account with the sysadmin server role to work. It needs to be fed credentials
through the script arguments or from the scripts 'mssql-brute' or 'mssql-empty-
password'.

When run, the script iterates over the credentials and attempts to run the command until either all
credentials are exhausted or until the command is executed.


SYNTAX:

mssql-hasdbaccess.limit:  limits the amount of databases per-user
that are returned (default 5). If set to zero or less all 
databases the user has access to are returned.



mssql.password:  specifies the password to use to connect to
the server. This option overrides any accounts found by
the 'ms-sql-brute' and 'ms-sql-empty-password' scripts.



mssql.username:  specifies the username to use to connect to
the server. This option overrides any accounts found by
the 'mssql-brute' and 'mssql-empty-password' scripts.



mssql.timeout:  How long to wait for SQL responses. This is a number
followed by 'ms' for milliseconds, 's' for seconds,
'm' for minutes, or 'h' for hours. Default:
'30s'.";

if(description)
{
    script_id(104086);
    script_version("$Revision: 10 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:03:59 +0100 (So, 27. Okt 2013) $");
    script_tag(name:"creation_date", value:"2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)");
    script_tag(name:"cvss_base", value:"4.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:SI/C:P/I:N/A:N");
    script_tag(name:"risk_factor", value:"Medium");
    script_name("Nmap NSE net: ms-sql-hasdbaccess");
    desc = "
    Summary:
    " + tag_summary;

    script_description(desc);

    script_summary("Nmap NSE net: ms-sql-hasdbaccess");
    script_category(ACT_INIT);
    script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
    script_family("Nmap NSE net");

    script_add_preference(name:"mssql-hasdbaccess.limit", value:"", type:"entry");
    script_add_preference(name:"mssql.password", value:"", type:"entry");
    script_add_preference(name:"mssql.username", value:"", type:"entry");
    script_add_preference(name:"mssql.timeout", value:"", type:"entry");

    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
}


include("nmap.inc");


phase = 0;
if (defined_func("scan_phase")) {
    phase = scan_phase();
}

if (phase == 1) {
    # Get the preferences
    argv = make_array();

    pref = script_get_preference("mssql-hasdbaccess.limit");
    if (!isnull(pref) && pref != "") {
        argv["mssql-hasdbaccess.limit"] = string('"', pref, '"');
    }
    pref = script_get_preference("mssql.password");
    if (!isnull(pref) && pref != "") {
        argv["mssql.password"] = string('"', pref, '"');
    }
    pref = script_get_preference("mssql.username");
    if (!isnull(pref) && pref != "") {
        argv["mssql.username"] = string('"', pref, '"');
    }
    pref = script_get_preference("mssql.timeout");
    if (!isnull(pref) && pref != "") {
        argv["mssql.timeout"] = string('"', pref, '"');
    }
    nmap_nse_register(script:"ms-sql-hasdbaccess", args:argv);
} else if (phase == 2) {
    res = nmap_nse_get_results(script:"ms-sql-hasdbaccess");
    foreach portspec (keys(res)) {
        output_banner = 'Result found by Nmap Security Scanner (ms-sql-hasdbaccess.nse) http://nmap.org:\n\n';
        if (portspec == "0") {
            security_warning(data:output_banner + res[portspec], port:0);
        } else {
            v = split(portspec, sep:"/", keep:0);
            proto = v[0];
            port = v[1];
            security_warning(data:output_banner + res[portspec], port:port, protocol:proto);
        }
    }
}
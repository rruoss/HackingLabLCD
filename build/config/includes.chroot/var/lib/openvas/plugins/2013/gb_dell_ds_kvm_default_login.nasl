###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_ds_kvm_default_login.nasl 11 2013-10-27 10:12:02Z jan $
#
# Dell KVM Default Login
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
# of the License, or (at your option) any later version
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103764";  

tag_summary = 'The remote Dell KVM is prone to a default account
authentication bypass vulnerability.';

tag_insight = 'It was possible to login with username "Admin" and an empty password.';

tag_impact = 'This issue may be exploited by a remote attacker to gain access to
sensitive information or modify system configuration without requiring authentication.';

tag_solution = 'Set a password.';
tag_vuldetect = 'This check tries to login into the remote KVM as Admin.';

if (description)
{
 
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-19 11:03:03 +0100 (Mon, 19 Aug 2013)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Dell KVM Default Login");

  desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Impact:
" + tag_impact + "

Solution:
" + tag_solution;

 script_description(desc);
 script_summary("Try to login with default credential");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports(443);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
 } 

 exit(0);
}

include("http_func.inc");
include("openvas-https.inc");

port = 443;

url = '/login.php';
req = http_get(item:url, port:port);

buf = https_req_get(port:port, request:req);

if(buf !~ "<title>[0-9]+(DS|AD) Explorer</title>" || "loginUsername" >!< buf)exit(0);

host = get_host_name();

req = 'POST /login.php HTTP/1.1\r\n' + 
      'Host: ' + host + '\r\n' + 
      'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/17.0 OpenVAS\r\n' + 
      'Accept-Encoding: Identity\r\n' + 
      'DNT: 1\r\n' + 
      'Connection: close\r\n' + 
      'Referer: https://' + host + ' /login.php\r\n' + 
      'Cookie: avctSessionId=; /home.php-t1s=1\r\n' + 
      'Content-Type: application/x-www-form-urlencoded\r\n' + 
      'Content-Length: 59\r\n' + 
      '\r\n' + 
      'action=login&loginUsername=Admin&loginPassword=&language=de';

buf = https_req_get(port:port, request:req);

if("302 Found" >!< buf || "/home.php" >!< buf) exit(0);

session = eregmatch(pattern:"avctSessionId=([0-9]+)", string:buf);

if(isnull(session[1]))exit(0);

avctSessionId = session[1];

req = 'GET /home.php HTTP/1.1\r\n' + 
      'Host: ' + host + '\r\n' + 
      'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/17.0 OpenVAS\r\n' +
      'Connection: close\r\n' +
      'Accept-Encoding: Identity\r\n' +
      'Accept-Language:en-us;\r\n' + 
      'Cookie: avctSessionId=' + avctSessionId + '\r\n\r\n';

buf = https_req_get(port:port, request:req);

if("Admin" >< buf && "/appliance-overview.php" >< buf && "/logout.php" >< buf) {

  security_hole(port:port);
  exit(0);

}

exit(99);



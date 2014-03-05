###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_57746.nasl 11 2013-10-27 10:12:02Z jan $
#
# Joomla! 'highlight' Parameter PHP Object Injection Vulnerability
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
tag_summary = "Joomla! is prone to a remote PHP object-injection vulnerability because it fails
to properly validate user-supplied input.

Attackers can exploit this issue to inject arbitrary object in to the
application. This may aid in further attacks.

The following versions are vulnerable:

Joomla! 2.0.0 through versions prior to 2.5.9
Joomla! 3.0.0 through versions prior to 3.0.3";


tag_solution = "Vendor updates are available. Please see the references for more
information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103673";
CPE = "cpe:/a:joomla:joomla";

if (description)
{
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "solution" , value : tag_solution);
     script_tag(name : "summary" , value : tag_summary);
 }
 script_oid(SCRIPT_OID);
 script_bugtraq_id(57746);
 script_cve_id("CVE-2013-1453");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
 script_version ("$Revision: 11 $");

 script_name("Joomla! 'highlight' Parameter PHP Object Injection Vulnerability");

desc = "
   Summary:
   " + tag_summary + "
 Solution:
 " + tag_solution;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/57746");
 script_xref(name : "URL" , value : "http://www.joomla.org/");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-03-03 10:29:04 +0100 (Sun, 03 Mar 2013)");
 script_description(desc);
 script_summary("Determine if installed Joomla is vulnerable to PHP Object Injection");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("joomla_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("joomla/installed");
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

url = dir + '/index.php?highlight=YToxOntpOjA7Tzo3OiJPcGVuVkFTIjowOnt9fQ=='; 

req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf =~ "HTTP/1.. 500" || "Catchable fatal error: Object of class __PHP_Incomplete_Class could not be converted to string" >< buf) {

  security_hole(port:port);
  exit(0);

}  

exit(99);


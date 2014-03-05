###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_scrutinizer_54726.nasl 12 2013-10-27 11:15:33Z jan $
#
# Scrutinizer Arbitrary File Upload Vulnerability
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
tag_summary = "Scrutinizer is prone to multiple vulnerabillities.

1. A vulnerability that lets attackers upload arbitrary files. The issue occurs
because the application fails to adequately sanitize user-supplied input.

An attacker may leverage this issue to upload arbitrary files to the
affected computer; this can result in arbitrary code execution within
the context of the vulnerable application.

2. A security-bypass vulnerability.
Successful attacks can allow an attacker to gain access to the affected application using
the default authentication credentials.

Scrutinizer 9.5.0 is vulnerable; other versions may also be affected.";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103528";
CPE = 'cpe:/a:dell:sonicwall_scrutinizer';

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(54726,54727);
 script_cve_id("CVE-2012-2627","CVE-2012-2626");
 script_tag(name:"cvss_base", value:"9.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");
 script_version ("$Revision: 12 $");

 script_name("Scrutinizer Arbitrary File Upload Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54726");
 script_xref(name : "URL" , value : "http://www.plixer.com");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-02 10:24:13 +0200 (Thu, 02 Aug 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to upload a file");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_scrutinizer_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("scrutinizer/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID))exit(0);

host = get_host_name();
file = "openvas_" + rand() + ".txt"; 
len = 195 + strlen(file);

req = string("POST ",dir,"/d4d/uploader.php HTTP/1.0\r\n",
             "Host: ", host,"\r\n",
             "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; OpenVAS 5)\r\n",
             "Content-Type: multipart/form-data; boundary=_Part_949_3365333252_3066945593\r\n",
             "Content-Length: ",len,"\r\n",
             "\r\n\r\n",
             "--_Part_949_3365333252_3066945593\r\n",
             "Content-Disposition: form-data;\r\n",
             'name="uploadedfile"; filename="', file,'"',"\r\n",
             "Content-Type: application/octet-stream\r\n",
             "\r\n",
             "OpenVAS\r\n",
             "\r\n",
             "--_Part_949_3365333252_3066945593--\r\n\r\n");

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if('"success":1' >< result && file >< result) {
  security_hole(port:port);
  exit(0);
}  
  
exit(0);


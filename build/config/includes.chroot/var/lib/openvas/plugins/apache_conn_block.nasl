# OpenVAS Vulnerability Test
# $Id: apache_conn_block.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Apache Connection Blocking Denial of Service
#
# Authors:
# Original script written by Tenable Network Security
# Modified by Scott Shebby scotts@scanalert.com
# OS check by George Theall
#
# Copyright:
# Copyright (C) 2004 Scott Shebby
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote web server appears to be running a version of 
Apache that is less that 2.0.49 or 1.3.31.

These versions are vulnerable to a denial of service attack where a remote 
attacker can block new connections to the server by connecting to a listening 
socket on a rarely accessed port.";

tag_solution = "Upgrade to Apache 2.0.49 or 1.3.31.";

if(description)
{
 script_id(12280);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(9921);
 script_cve_id("CVE-2004-0174");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 name = "Apache Connection Blocking Denial of Service";

 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Checks for version of Apache";

 script_summary(summary);

 script_category(ACT_GATHER_INFO);


 script_copyright("This script is Copyright (C) 2004 Scott Shebby");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("http_version.nasl", "os_fingerprint.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("backport.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!port) exit(0);
if(!get_port_state(port))exit(0);

# nb: don't bother checking if platform is known to be unaffected. (george theall)
if (host_runs("FreeBSD|Linux") == "yes") exit(0);


banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);

serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.([0-9][^0-9]|[0-3][0-9]|4[0-8])", string:serv))
 {
   security_warning(port);
   exit(0);
 }
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.|3\.([0-9][^0-9]|[0-2][0-9]|30)))", string:serv))
 {
   security_warning(port);
   exit(0);
 }

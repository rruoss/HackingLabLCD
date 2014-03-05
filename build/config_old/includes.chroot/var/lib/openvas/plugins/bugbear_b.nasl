# OpenVAS Vulnerability Test
# $Id: bugbear_b.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Bugbear.B web backdoor
#
# Authors:
# StrongHoldNet
# Modifications by rd:
#  -> Try every web server, not just port 81
#
# Copyright:
# Copyright (C) 2003 StrongHoldNet
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
tag_summary = "Your system seems to be infected by the Bugbear.B virus
(its backdoor has been detected on port 81).

More information: http://www.f-secure.com/v-descs/bugbear_b.shtml";

tag_solution = "Use your favorite antivirus to disinfect your
system. Standalone disinfection tools also exist :
ftp://ftp.f-secure.com/anti-virus/tools/f-bugbr.zip";

# Ref: http://www.f-secure.com/v-descs/bugbear_b.shtml

if (description)
{
 script_id(11707);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Bugbear.B web backdoor");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_summary("Checks for Bugbear.B web backdoor");
 script_category(ACT_GATHER_INFO);
 script_family("Malware");
 script_copyright("This script is Copyright (C) 2003 StrongHoldNet");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 81);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:81);
if(!port)exit(0);

if(!get_port_state(port))exit(0);
url = string(d, '/%NETHOOD%/');
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req);
if( buf == NULL ) exit(0);
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) && "Microsoft Windows Network" >< buf) security_hole(port);


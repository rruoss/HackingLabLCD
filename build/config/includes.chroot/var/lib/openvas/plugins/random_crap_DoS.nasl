# OpenVAS Vulnerability Test
# $Id: random_crap_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Kill service with random data
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
tag_summary = "It was possible to crash the remote service by sending it
a few kilobytes of random data.

An attacker may use this flaw to make this service crash continuously, 
preventing this service from working properly. It may also be possible
to exploit this flaw to execute arbitrary code on this host.";

tag_solution = "upgrade your software or contact your vendor and inform it of this
vulnerability";

# References
#
# http://www.securityfocus.com/bid/158/
# Exceed Denial of Service Vulnerability
# CVE-1999-1196

if(description)
{
 script_id(17296);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(158);
 script_cve_id("CVE-1999-1196");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "Kill service with random data";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Sends random data to the remote service";
 script_summary(summary);
 
 # Maybe we should set this to ACT_DESTRUCTIVE_ATTACK only?
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service.nasl", "find_service2.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
include("global_settings.inc");
if (! experimental_scripts) exit(0);

beurk = '';
for (i = 0; i < 256; i ++)
 beurk = strcat(beurk, 
  ord(rand() % 256), ord(rand() % 256), ord(rand() % 256), ord(rand() % 256),
  ord(rand() % 256), ord(rand() % 256), ord(rand() % 256), ord(rand() % 256));
# 2 KB

ports = get_kb_list("Ports/tcp/*");
if (isnull(ports)) exit(0);

foreach port (keys(ports))
{
 port = int(port - "Ports/tcp/");
 soc = open_sock_tcp(port);
 if (soc)
 {
   send(socket: soc, data: beurk);
   close(soc);

  # Is the service still alive?
  # Retry just in case it is rejecting connections for a while
  for (i = 1; i <= 3; i ++)
  {
    soc = open_sock_tcp(port);
    if (soc) break;
    sleep(i);
  }
  if (! soc)
   security_warning(port);
  else
   close(soc);
 }
}

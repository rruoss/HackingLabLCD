# OpenVAS Vulnerability Test
# $Id: rsync_path_sanitation_vuln.nasl 17 2013-10-27 14:01:43Z jan $
# Description: rsync path sanitation vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
tag_summary = "A vulnerability has been reported in rsync, which potentially can be exploited 
by malicious users to read or write arbitrary files on a vulnerable system.

rsync is a software product for keeping files synched across multiple
systems.  Rsync is a network-based program and typically communicates
over TCP port 873.  

There is a flaw in this version of rsync which, due to an input validation
error, would allow a remote attacker to gain access to the remote system.

An attacker, exploiting this flaw, would need network access to the TCP port.  

Successful exploitation requires that the rsync daemon is *not* running chrooted.

*** Since rsync does not advertise its version number
*** and since there are little details about this flaw at
*** this time, this might be a false positive";

tag_solution = "Upgrade to rsync 2.6.3 or newer";

# Ref: Reported by vendor

if (description)
{
 script_id(14223);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(10938);
 script_cve_id("CVE-2004-0792");
  

 script_name("rsync path sanitation vulnerability");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_tag(name:"risk_factor", value:"High");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 script_summary("Determines if rsync is running");
 script_category(ACT_GATHER_INFO);
 script_family("Gain a shell remotely");
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 script_dependencies("rsync_modules.nasl");
 script_require_ports("Services/rsync", 873);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include('global_settings.inc');

if ( report_paranoia < 1 ) exit(0);


port = get_kb_item("Services/rsync");
if(!port)port = 873;
if(!get_port_state(port))exit(0);


welcome = get_kb_item("rsync/" + port + "/banner");
if ( ! welcome )
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 welcome = recv_line(socket:soc, length:4096);
 if(!welcome)exit(0);
}




#
# rsyncd speaking protocol 28 are not vulnerable
#

if(ereg(pattern:"@RSYNCD: (1[0-9]|2[0-8])", string:welcome))
{
 security_hole(port);
}

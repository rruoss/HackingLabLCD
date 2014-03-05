# OpenVAS Vulnerability Test
# $Id: winsatan.nasl 17 2013-10-27 14:01:43Z jan $
# Description: WinSATAN
#
# Authors:
# Julio César Hernández <jcesar@inf.uc3m.es>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added link to the Bugtraq message archive
#
# Copyright:
# Copyright (C) 2000 Julio César Hernández
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
tag_summary = "WinSATAN is installed. 

This backdoor allows anyone to partially take control
of the remote system.

An attacker may use it to steal your password or prevent
your system from working properly.";

tag_solution = "use RegEdit, and find 'RegisterServiceBackUp'
in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
The value's data is the path of the file.
If you are infected by WinSATAN, then
the registry value is named 'fs-backup.exe'.

Additional Info : http://online.securityfocus.com/archive/75/17508
Additional Info : http://online.securityfocus.com/archive/75/17663";


if(description)
{
 script_id(10316);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 
 name = "WinSATAN";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;



 script_description(desc);
 
 summary = "Checks for the presence of WinSATAN";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2000 Julio César Hernández");
 family = "Malware";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports(999);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
include('ftp_func.inc');
if(get_port_state(999))
{
soc = open_sock_tcp(999);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:"uyhw6377w", pass:"bhw32qw"))security_hole(999);
 close(soc);
}
}

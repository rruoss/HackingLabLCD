# OpenVAS Vulnerability Test
# $Id: mssql_ping.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Microsoft's SQL UDP Info Query
#
# Authors:
# H D Moore
#
# Copyright:
# Copyright (C) 2001 H D Moore
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
tag_summary = "It is possible to determine remote SQL server version

Description :

Microsoft SQL server has a function wherein remote users can
query the database server for the version that is being run.
The query takes place over the same UDP port which handles the
mapping of multiple SQL server instances on the same machine.

CAVEAT: It is important to note that, after Version 8.00.194,
Microsoft decided not to update this function.  This means that
the data returned by the SQL ping is inaccurate for newer releases
of SQL Server.";

tag_solution = "filter incoming traffic to this port";

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


if(description)
{
 script_id(10674);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "Microsoft's SQL UDP Info Query";
 script_name(name);
 
 script_description(desc);
 
 summary = "Microsoft's SQL UDP Info Query";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2001 H D Moore");
 family = "Windows";
 script_family(family);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

##
# data returned will look like:
#
#   xServerName;REDEMPTION;InstanceName;MSSQLSERVER;IsClustered;No;Version;8.00.194;tcp;1433;np;\\REDEMPTION\pipe\sql\query;;
#
##

# this magic info request packet
req = raw_string(0x02);


if(!get_udp_port_state(1434))exit(0);

soc = open_sock_udp(1434);


if(soc)
{
	send(socket:soc, data:req);
	r  = recv(socket:soc, length:4096);
	close(soc);
	if(!r)exit(0);
	set_kb_item(name:"MSSQL/UDP/Ping", value:TRUE);
        r = strstr(r, "Server");
        r = str_replace(find:";", replace:" ", string:r);
	if(r)
	{
 		report += string("OpenVAS sent an MS SQL 'ping' request. The results were : \n", r, "\n\n");
                report += string("If you are not running multiple instances of Microsoft SQL Server\n");
                report += string("on the same machine, It is suggested you filter incoming traffic to this port");

		 report = string (desc,
				"\n\nPlugin output :\n\n",
				report);

		if("version" >< tolower(r)) { 
                  version = eregmatch(pattern:"Version ([0-9.]+)", string:r);
		  if(!isnull(version[1])) {
                    set_kb_item(name:"mssql/remote_version", value:version[1]);
		  }  
		}  

		security_note(port:1434, protocol:"udp", data:report);
		set_kb_item(name:"mssql/udp/1434", value:TRUE);
	}
}

# OpenVAS Vulnerability Test
# $Id: DDI_warftpd_user_overflow.nasl 17 2013-10-27 14:01:43Z jan $
# Description: War FTP Daemon USER/PASS Overflow
#
# Authors:
# Erik Tayler <erik@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2003 Digital Defense, Inc.
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
tag_summary = "The version of War FTP Daemon running on this host contains
a buffer overflow in the code that handles the USER and PASS
commands. A potential intruder could use this vulnerability
to crash the server, as well as run arbitrary commands on
the system.";

tag_solution = "Upgrade to the latest release of the War FTP Daemon
           available from the following web site: http://www.jgaa.com/";

if(description)
{
	script_id(11207);
	script_version("$Revision: 17 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
	script_bugtraq_id(10078);
	script_cve_id("CVE-1999-0256");
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name:"risk_factor", value:"High");
	
	name = "War FTP Daemon USER/PASS Overflow";
	script_name(name);
	desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
	script_description(desc);
	summary = "War FTP Daemon USER/PASS Overflow";
	script_summary(summary);
	script_category(ACT_GATHER_INFO);
	script_copyright("This script is Copyright (C) 2003 Digital Defense, Inc.");
	family = "FTP";
	script_family(family);
	script_dependencies("ftpserver_detect_type_nd_version.nasl");
	script_require_ports("Services/ftp", 21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
	exit(0);
}


include("ftp_func.inc");

port = get_kb_item("Services/ftp");

if(!port)port = 21;

if(get_port_state(port))
{
	r = get_ftp_banner(port:port);
	if(!r)exit(0);

	if(egrep(pattern:"WAR-FTPD 1.([0-5][0-9]|6[0-5])[^0-9]*Ready",string:r, icase:TRUE))
	{
		security_hole(port);
	}
}
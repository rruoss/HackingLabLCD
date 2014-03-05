# OpenVAS Vulnerability Test
# $Id: openssh_uselogin_environment.nasl 17 2013-10-27 14:01:43Z jan $
# Description: OpenSSH UseLogin Environment Variables
#
# Authors:
# EMAZE Networks S.p.A.
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
# changes by rd: description, static report
#
# Copyright:
# Copyright (C) 2001 EMAZE Networks S.p.A.
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
tag_summary = "You are running a version of OpenSSH which is older than 3.0.2.

Versions prior than 3.0.2 are vulnerable to an environment
variables export that can allow a local user to execute
command with root privileges.
This problem affect only versions prior than 3.0.2, and when
the UseLogin feature is enabled (usually disabled by default)";

tag_solution = "Upgrade to OpenSSH 3.0.2 or apply the patch for prior
versions. (Available at: ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH)";

if(description)
{
 	script_id(10823);
 	script_version("$Revision: 17 $");
 	script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 	script_bugtraq_id(3614);
	script_xref(name:"IAVA", value:"2001-t-0017");
	script_cve_id("CVE-2001-0872");
    script_tag(name:"cvss_base", value:"7.2");
    script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
    script_tag(name:"risk_factor", value:"High");
 	name = "OpenSSH UseLogin Environment Variables";
	script_name(name);
 
 	desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;	
 	script_description(desc);
 
 	summary = "Checks for the remote SSH version";
 	script_summary(summary);
 
 	script_category(ACT_GATHER_INFO);
 
 
 	script_copyright("This script is copyright (C) 2001 by EMAZE Networks S.p.A.");
  	
	family = "Gain a shell remotely";
 	script_family(family);
 	
	script_dependencies("ssh_detect.nasl");
 	script_require_ports("Services/ssh", 22);
 
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
 	exit(0);
}


#
# The script code starts here
#

include("backport.inc");

port = get_kb_item("Services/ssh");
if(!port) port = 22;

banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);

banner = tolower(get_backport_banner(banner:banner));

if(ereg(pattern:"ssh-.*-openssh[-_](1\..*|2\..*|3\.0.[0-1]).*" , string:text)) 
	{
		security_hole(port);
	}

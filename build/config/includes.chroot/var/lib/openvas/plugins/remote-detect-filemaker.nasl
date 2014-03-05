# OpenVAS Vulnerability Test
# $Id: remote-detect-filemaker.nasl 42 2013-11-04 19:41:32Z jan $
# Description: This script ensure that the FileMaker database server is installed
#
# remote-detect-filemaker.nasl 
#
# Authors:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
# Slight modification by Vlatko Kosturjak - Kost <kost@linux.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
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
tag_summary = "The remote host is running the Filemaker database server. 
FileMaker Pro is a cross-platform relational database application from FileMaker Inc., 
a subsidiary of Apple Inc., has compatible versions for both the Mac OS X and Microsoft Windows operating systems";

tag_solution = "You should Allow connection to this host only from trusted host or networks,
or disable the service if not used.";

if(description)
{
script_id(80003);
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
script_tag(name:"creation_date", value:"2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)");
script_tag(name:"cvss_base", value:"0.0");
script_tag(name:"risk_factor", value:"None");
name = "FileMaker service detection";
script_name(name);
 
 desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;
script_description(desc);

summary = " Ensure that the Filemaker database server is running";

script_summary(summary);

script_category(ACT_GATHER_INFO);

script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
family = "Service detection";
script_family(family);
script_require_ports(5003);

if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
}
 exit(0);
}

# deifine the default port for Filemaker
port = 5003;

# Forge the filemaker evil request

filemaker_auth_packet =    "0x470x490x4f0x500x010x020x010x000x140x010x000x000x040x000x000x00";
filemaker_auth_packet +=  "0x030x000x000x000x000x000x000x000x170x000x000x000xff0x6f0x6d0x6e";
filemaker_auth_packet +=  "0x690x490x4e0x530x500x4f0x410xff0x460x4d0x500x4f0x410x000x460x4d";
filemaker_auth_packet +=  "0x520x500x4f0x000x080x000x000x000x430x6f0x6e0x6e0x650x630x740x00";
filemaker_auth_packet +=  "0x000x000x000x000x050x000x000x000x0c0x000x000x000x490x440x4c0x3a";
filemaker_auth_packet +=  "0x520x500x4f0x3a0x310x2e0x300x000x010x000x000x000x000x000x000x00";
filemaker_auth_packet +=  "0x6c0x000x000x000x010x010x020x000x0b0x000x000x000x310x300x2e0x34";
filemaker_auth_packet +=  "0x2e0x310x310x2e0x390x340x000x000x8b0x130x000x000x170x000x000x00";
filemaker_auth_packet +=  "0xff0x6f0x6d0x6e0x690x490x4e0x530x500x4f0x410xff0x460x4d0x500x4f";
filemaker_auth_packet +=  "0x410x000x460x4d0x520x500x4f0x000x020x000x000x000x000x000x000x00";
filemaker_auth_packet +=  "0x080x000x000x000x010x000x000x000x000x540x540x410x010x000x000x00";
filemaker_auth_packet +=  "0x1c0x000x000x000x010x000x000x000x010x000x010x000x010x000x000x00";
filemaker_auth_packet +=  "0x010x000x010x050x090x010x010x000x010x000x000x000x090x010x010x00";
filemaker_auth_packet +=  "0x4c0x000x000x000x010x010x080x2d0x220x2a0x3f0x340x290x2a0x680x23";
filemaker_auth_packet +=  "0x690x620x0c0x6e0x6f0x0e0x170x170x630x140x140x0e0x620x6c0x6e0x63";
filemaker_auth_packet +=  "0x0c0x6d0x630x6f0x690x6f0x6d0x680x0e0x100x170x0c0x170x680x020x14";
filemaker_auth_packet +=  "0x110x0e0x0e0x090x0a0x280x350x7a0x620x740x6a0x2c0x6b0x110x6a0x6a";
filemaker_auth_packet +=  "0x600x6a0x390x600x680x630x600x6f0x690x600x390x6e0x600x6c0x3b0x15";

# declare that Filemaker is not installed yet
is_filemaker = 0;

if(get_port_state(port))
{
	soc = open_sock_tcp(port);
	if(soc)
	{
		 
		send(socket:soc, data: filemaker_auth_packet);
		reply = recv(socket:soc, length:136);

		# Check that Filemaker is not tcpwrapped. And that it's really Filemaker

		if(stridx(reply, "GIOP", 0)) is_filemaker = 1;
		close(soc);
	}
}

#
# Report Filemaker installed
#  
if(is_filemaker == 1)
{
set_kb_item (name:"FileMaker/installed", value:TRUE);
security_note(port);
}
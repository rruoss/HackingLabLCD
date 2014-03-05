# OpenVAS Vulnerability Test
# $Id: remote-detect-firebird.nasl 42 2013-11-04 19:41:32Z jan $
# Description: This script ensure that a Firebase/Interbase database server is installed and running
#
# remote-detect-firebird.nasl
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
tag_summary = "The remote host is running the Firebase/Interbase database Server. 
Firebird is a RDBMS offering many ANSI SQL:2003 features. 
It runs on Linux, Windows, and a variety of Unix platforms 
and Started as a fork of Borland's open source release of InterBase";

tag_solution = "It's recommended to allow connection to this host only from trusted hosts or networks,
or disable the service if not used.";



if(description)
{
script_id(80004);
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
script_tag(name:"creation_date", value:"2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)");
script_tag(name:"cvss_base", value:"0.0");
script_tag(name:"risk_factor", value:"None");
name = "Firebase/Interbase database Server service detection";
script_name(name);
 
desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;
script_description(desc); 

summary = "Ensure that the remote host is running a Firebird/Interbase database server ";

script_summary(summary);

script_category(ACT_GATHER_INFO);

script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
family = "Service detection";
script_family(family);
script_dependencies("find_service.nasl");
script_require_ports("Services/unknown", 3050);


if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
}
exit(0);

}

#
# The script code starts here
#

include("misc_func.inc");

port = 3050;
reponse = "";

# forge the firebird negociation protocol

firebird_auth_packet   = raw_string(
0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x13,0x00,0x00,0x00,0x02,0x00,
0x00,0x00,0x24,0x00,0x00,0x00,0x1c,0x2f,0x6f,0x70,0x74,0x2f,0x66,
0x69,0x72,0x65,0x62,0x69,0x72,0x64,0x2f,0x62,0x69,0x6e,0x2f,0x6c,
0x65,0x67,0x69,0x6f,0x6e,0x2e,0x66,0x64,0x62,0x00,0x00,0x00,0x02,
0x00,0x00,0x00,0x17,0x01,0x04,0x72,0x6f,0x6f,0x74,0x04,0x09,0x63,
0x68,0x72,0x69,0x73,0x74,0x69,0x61,0x6e,0x05,0x04,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
0x02,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x0a,
0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x03,0x00,
0x00,0x00,0x04);
 

# Connect to remote Firebird/Interbase server
if(get_port_state(port)) soc = open_sock_tcp(port);
if(soc)
{

	send(socket:soc, data:firebird_auth_packet);
	response = recv(socket:soc, length:1024);

	close(soc);

        if(!isnull(response) && strlen(response) == 16 && "030000000a0000000100000003" >< hexstr(response)) {
	  register_service(port:port, ipproto:"tcp", proto:"gds_db");
          security_note(port:port);
	  exit(0);
        }
}

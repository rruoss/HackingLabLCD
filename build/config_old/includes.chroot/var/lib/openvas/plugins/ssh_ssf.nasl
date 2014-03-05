# OpenVAS Vulnerability Test
# $Id: ssh_ssf.nasl 16 2013-10-27 13:09:52Z jan $
# Description: SSF Detection
#
# Authors:
# Michel Arboi
#
# Copyright:
# Copyright (C) 2008 Michel Arboi
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
tag_summary = "The remote version of the SSH server is not maintained
any more.

Description :

According to its banner, the remote SSH server is the
SSF derivative.

SSF had been written to be compliant with restrictive 
laws on cryptography in some European countries, France 
especially. 

These regulations have been softened and OpenSSH received 
a formal authorisation from the French administration in 
2002 and the development of SSF has been discontinued.

SSF is based upon an old version of OpenSSH and it implements
an old version of the protocol. As it is not maintained any
more, it might be vulnerable to dangerous flaws.";

tag_solution = "Remove SSF and install an up to date version of OpenSSH.";

# http://perso.univ-rennes1.fr/bernard.perrot/SSF/index.html
# http://ccweb.in2p3.fr/secur/ssf/

if(description)
{
 script_id(80087);;
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name( "SSF Detection");
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 script_summary( "Look for SSF in the SSH banner");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2008 Michel Arboi");
 script_family( "General");
 script_dependencies("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://ccweb.in2p3.fr/secur/ssf/");
 script_xref(name : "URL" , value : "http://perso.univ-rennes1.fr/bernard.perrot/SSF/");
 exit(0);
}

include('misc_func.inc');

port = get_kb_item("Services/ssh");
if (! port) port = 22;
if (! get_port_state(port)) exit(0);

banner = get_unknown_banner(port: port);
if (egrep(string: banner, pattern: "^SSH-[0-9.]+-SSF"))
 security_note(port);


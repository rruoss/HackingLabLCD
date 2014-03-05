# OpenVAS Vulnerability Test
# $Id: citrix_find.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Check for a Citrix server
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net
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
tag_summary = "A Citrix server is running on this machine.

Citrix servers allow a Windows user to remotely
obtain a graphical login (and therefore act as a local
user on the remote host). 

NOTE: by default the Citrix Server application 
utilizes a weak 40 bit obfuscation algorithm (not
even a true encryption).  If the default settings have
not been changed, there already exists tools which can
be used to passively ferret userIDs and passwords as they
traverse a network.

If this server is located within your DMZ, the risk is
substantially higher, as Citrix necessarily requires
access into the internal network for applications like
SMB browsing, file sharing, email synchronization, etc.

If an attacker gains a valid login and password, he may
be able to use this service to gain further access on
the remote host or remote network. This protocol has also
been shown to be  vulnerable to a man-in-the-middle attack.";

tag_solution = "Disable this service if you do not use it. Also, make sure
that the server is configured to utilize strong encryption.";

if(description)
{
 script_id(10942);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(7276);
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");
 name = "Check for a Citrix server";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 summary = "CITRIX check";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net");
 family = "Useless services";
 script_family(family);
 script_require_ports(1494);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#





function check_setting(port) {
 if(!get_port_state(port))exit(0);
 soc = open_sock_tcp(port);
 if(soc) {
    r = recv(socket:soc, length:64);
    if ((egrep(pattern:".*ICA.*", string:r))) {
        security_note(port);
    }
    close(soc);
 }
}

port = 1494;
check_setting(port:port);

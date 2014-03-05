###############################################################################
# OpenVAS Vulnerability Test
# $Id: telnet.nasl 43 2013-11-04 19:51:40Z jan $
#
# Check for Telnet
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "A telnet Server is running at this host.

   Experts in computer security, such as SANS Institute, and the members of the
   comp.os.linux.security newsgroup recommend that the use of Telnet for remote
   logins should be discontinued under all normal circumstances, for the following
   reasons:

   * Telnet, by default, does not encrypt any data sent over the connection
     (including passwords), and so it is often practical to eavesdrop on the
     communications and use the password later for malicious purposes; anybody who
     has access to a router, switch, hub or gateway located on the network between
     the two hosts where Telnet is being used can intercept the packets passing by
     and obtain login and password information (and whatever else is typed) with any
     of several common utilities like tcpdump and Wireshark.
    
   * Most implementations of Telnet have no authentication that would ensure
     communication is carried out between the two desired hosts and not intercepted
     in the middle.

   * Commonly used Telnet daemons have several vulnerabilities discovered over
     the years.";


if(description)
{
 script_id(100074);
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-03-24 15:43:44 +0100 (Tue, 24 Mar 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");

 name = "Check for Telnet Server";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 summary = "Check for Telnet Server";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 family = "General";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/telnet", 23);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");
include("telnet_func.inc");

port = get_kb_item("Services/telnet");

if(!port)port = 23;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

  banner = telnet_negotiate(socket:soc);  
  if(strlen(banner) > 3)
  {
   register_service(port:port, proto:"telnet");
   set_telnet_banner(port: port, banner: banner);
   security_note(port:port);
   exit(0);
 }

exit(0);

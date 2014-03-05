# OpenVAS Vulnerability Test
# $Id: check_ports.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Check open ports
#
# Authors:
# Michel Arboi <arboi@alussinan.org> 
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
tag_summary = "This plugin checks if the port scanners did not kill a service.";

# Services known to crash or freeze on a port scan:
#
# ClearCase (TCP/371)
# NetBackup

# References
#
# From: marek.rouchal@infineon.com
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org, 
#   submissions@packetstormsecurity.org
# CC: rheinold@rational.com, buggy@segmentationfault.de, 
#    Thorsten.Delbrouck@guardeonic.com, manfred.korger@infineon.com
# Date: Fri, 22 Nov 2002 10:30:11 +0100
# Subject: ClearCase DoS vulnerabilty

if(description)
{
 script_id(10919);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_name("Check open ports");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Check if ports are still open");
 script_category(ACT_END);

 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 script_family("General");

 script_dependencies("find_service.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


ports = get_kb_list("Ports/tcp/*");
if(isnull(ports))exit(0);

at_least_one = 0;
number_of_ports = 0;
report = make_list();
timeouts = 0;

foreach port (keys(ports))
{
   number_of_ports ++;
   port = int(port - "Ports/tcp/");
   to = get_kb_item("/tmp/ConnectTimeout/TCP/"+port);
   if (to)
     timeouts++;
   else
   {
   s = open_sock_tcp(port, transport:ENCAPS_IP);
   if (! s)
    {
    report[port] = 
'This port was detected as being open by a port scanner but is now closed.\n' +
'This service might have been crashed by a port scanner or by a plugin\n';
    }
   else
    {
    close(s);
    at_least_one ++;
    }
   }
}


if( number_of_ports == 0 )exit(0);

if(at_least_one > 0 || number_of_ports == 1)
{
 foreach port (keys(report))
 {
  security_note(port:port, data:report[port]);
 }
}
else
{
 text = "
OpenVAS cannot reach any of the previously open ports of the remote
host at the end of its scan.
";
 if (timeouts > 0)
 {
   text = "
** ";
   if (timeouts == number_of_ports)
    text += "All ports";
   else
    text = strcat(text, "Some of the ports (", timeouts, "/", number_of_ports, ")");
   text += " were skipped by this check because some
** scripts could not connect to them before the defined timeout
";
 }
 text += "
This might be an availability problem related which might be
due to the following reasons :

- The remote host is now down, either because a user turned it
off during the scan";

 if(safe_checks() == 0) text += 
" or a selected denial of service was effective against 
this host";

text += '

- A network outage has been experienced during the scan, and the remote 
network cannot be reached from the OpenVAS server any more

- This OpenVAS server has been blacklisted by the system administrator
or by automatic intrusion detection/prevention systems which have detected the 
vulnerability assessment.


In any case, the audit of the remote host might be incomplete and may need to
be done again
';

 security_note(port:0, data:text); 
}

# OpenVAS Vulnerability Test
# $Id: PC_anywhere_tcp.nasl 41 2013-11-04 19:00:12Z jan $
# Description: pcAnywhere TCP
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
# Changes by Tenable Network Security : cleanup + better detection
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
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
tag_summary = "pcAnywhere is running on this port";

tag_solution = "Disable this service if you do not use it.";

if(description)
{
 script_id(10794);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "pcAnywhere TCP";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 summary = "Checks for the presence pcAnywhere";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 Alert4Web.com");

 family = "Windows";
 script_family(family);
 script_dependencies("os_fingerprint.nasl", "find_service.nasl");
 script_require_ports("Services/unknown", 5631);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");
include("global_settings.inc");
include("host_details.inc");

if (host_runs("Windows") != "yes")
  exit(0);


function probe(port)
{
 soc = open_sock_tcp(port);
 if(soc)
 {
    send(socket:soc, data:raw_string(0,0,0,0));
    r = recv(socket:soc, length:36);
    if (r && ("Please press <" >< r))
    {
       register_service(port:port, proto:"pcanywheredata");
       security_note(port);
       exit(0);
    }
  close(soc);
 }
}



if ( thorough_tests ) port = get_kb_item("Services/unknown");
else port = 0;

if(port)
{
 if (! service_is_unknown (port: port)) exit(0);
 if(get_port_state(port))
  probe(port:port);
}
else 
{
 if(get_port_state(5631))
  probe(port:5631);
}

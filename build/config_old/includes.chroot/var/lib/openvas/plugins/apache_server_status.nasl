# OpenVAS Vulnerability Test
# $Id: apache_server_status.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Apache /server-status accessible
#
# Authors:
# Vincent Renardias <vincent@strongholdnet.com>
#
# Copyright:
# Copyright (C) 2001 StrongHoldNet
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

if(description)
{
 tag_summary = "Leak of information in Apache.";
 tag_vuldetect = "Check if /server-status page exist.";
 tag_insight = "server-status is a built-in Apache HTTP Server handler used to
retrieve the server's status report.";
 tag_impact = "Requesting the URI /server-status gives information about
the currently running Apache.";
 tag_affected = "All Apache version.";
 tag_solution = "If you don't use this feature, comment the appropriate section in
your httpd.conf file. If you really need it, limit its access to
the administrator's machine.";

 desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){                                                                                  
   script_tag(name : "summary" , value : tag_summary);                                                                                   
   script_tag(name : "vuldetect" , value : tag_vuldetect);                                                                               
   script_tag(name : "solution" , value : tag_solution);                                                                                 
   script_tag(name : "insight" , value : tag_insight);                                                                                   
   script_tag(name : "affected" , value : tag_affected);                                                                                 
   script_tag(name : "impact" , value : tag_impact);                                                                                     
 }

 script_id(10677);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)"); 
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 
 script_name("Apache /server-status accessible");
 
 script_description(desc);
 
 summary = "Makes a request like http://www.example.com/server-status";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2001 StrongHoldNet");
 script_family("General");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
str = "Apache Server Status";

if(get_port_state(port))
{
  buffer = http_get(item:"/server-status", port:port);
  data = http_keepalive_send_recv(port:port, data:buffer);
  if( str >< data )
  {
   security_warning(port);
  }
}

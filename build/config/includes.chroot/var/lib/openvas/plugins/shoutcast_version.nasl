# OpenVAS Vulnerability Test
# $Id: shoutcast_version.nasl 17 2013-10-27 14:01:43Z jan $
# Description: SHOUTcast Server DoS detector vulnerability
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2000 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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
tag_solution = "Upgrade to the latest version of SHOUTcast Server.

Additional information:
http://www.securiteam.com/exploits/5YP031555Q.html";

tag_summary = "This detects SHOUTcast Server's version. If the version equals 
1.8.2 it is vulnerable to a denial of service attack.";


if(description)
{
 script_id(10717); 
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
script_cve_id("CVE-2001-1304");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "SHOUTcast Server DoS detector vulnerability";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "SHOUTcast Server DoS detector vulnerability";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "General";
 script_family(family);

 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 8000);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

 port = get_kb_item("Services/www");
 if (!port) port = 8000;

 if (get_port_state(port))
 {
   req = 'GET /content/nonexistant' + rand() + rand() + rand() + '.mp3 HTTP/1.0\r\n\r\n' +
         'Host: ' + get_host_name() + '\r\n\r\n';
    banner = http_keepalive_send_recv(port:port, data:req);
   if(!banner)exit(0);
   if ("SHOUTcast Distributed Network Audio Server" >< banner)
   {
    resultrecv = banner;
    resultrecv = strstr(resultrecv, "SHOUTcast Distributed Network Audio Server/");
    resultsub = strstr(resultrecv, string("<BR>"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "SHOUTcast Distributed Network Audio Server/";
    resultrecv = resultrecv - "<BR>";
    report = string("The remote SHOUTcast server version is :\n");
    report = report + resultrecv;
    if ("1.8.2" >< resultrecv)
    {
     report = report + string("\n\nThis version of SHOUTcast is supposedly vulnerable to a denial of service attack. Upgrade your SHOUTcast server.\n");
     security_warning(port:port, data:report);
    }
    else
    {
     security_note(port:port, data:report);
    }
   } 
 }

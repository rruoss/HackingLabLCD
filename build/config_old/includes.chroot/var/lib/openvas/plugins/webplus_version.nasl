# OpenVAS Vulnerability Test
# $Id: webplus_version.nasl 17 2013-10-27 14:01:43Z jan $
# Description: TalentSoft Web+ version detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Changes by rd :
#  - use of function to simplify code
#
# Copyright:
# Copyright (C) 2000 SecuriTeam
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
tag_summary = "This plug-in detects the version of Web+ CGI. The Web+ CGI has a known 
vulnerability that enables a remote attacker to gain access to local files.

This bug is known to exist in Web+ 4.X as of March 1999, and probably exists 
in all previous versions as well.

This test in itself does not verify the vulnerability but rather tries to 
discover the version of Web+ which is installed.";

if(description)
{
 
 script_id(10373);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"3.3");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 name = "TalentSoft Web+ version detection";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Get the version of Web+ CGI";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2000 SecuriTeam");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

function extract_version(result, port)
{

    resultrecv = strstr(result, "Version: </b>: ");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "</b>";

    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "<br><b>Web+ Server Compile Number</b>: ");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<br>";
    resultrecv = resultrecv - "<b>";
    resultrecv = resultrecv - "</b>";

    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "<br><b>Web+ Client Compile Number</b>: ");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<br>";
    resultrecv = resultrecv - "<b>";
    resultrecv = resultrecv - "</b>";

    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "<br><b>Operating System</b>: ");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<br>";
    resultrecv = resultrecv - "<b>";
    resultrecv = resultrecv - "</b>";

    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "Web+ Server Version");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<B>";
    resultrecv = resultrecv - "</B>";
    
    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "Web+ Monitor Server Version");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<B>";
    resultrecv = resultrecv - "</B>";
    
    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "Web+ Client Version");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<B>";
    resultrecv = resultrecv - "</B>";
    
    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "Release Date");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<B>";
    resultrecv = resultrecv - "</B>";
    
    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "User Name");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<B>";
    resultrecv = resultrecv - "</B>";
    resultrecv = resultrecv - "<i>";
    resultrecv = resultrecv - "</i>";
    resultrecv = resultrecv - "<BR>";
    
    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "Company Name");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<B>";
    resultrecv = resultrecv - "</B>";
    resultrecv = resultrecv - "<i>";
    resultrecv = resultrecv - "</i>";
    resultrecv = resultrecv - "<BR>";
    
    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "Web Server IP Address");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<B>";
    resultrecv = resultrecv - "</B>";
    resultrecv = resultrecv - "&nbsp;</CENTER>";
    
    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "Web Server Domain Name");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "</B>";
    resultrecv = resultrecv - "&nbsp;</CENTER>";
    
    banner = banner + resultrecv;
    banner = banner + string("\n");
    
    security_warning(port:port, data:banner);
    return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


foreach dir (cgi_dirs())
{
req1 = string(dir, "/webplus?about");
req1 = http_get(item:req1, port:port);
req2 = string(dir, "/webplus.exe?about");
req2 = http_get(item:req2, port:port);

result = http_keepalive_send_recv(port:port, data:req1);
if(result == NULL)exit(0);

if("TalentSoft Web+" >< result)
 {
  extract_version(result:result, port:port);
  exit(0);
 }

result = http_keepalive_send_recv(port:port, data:req2);
if("TalentSoft Web" >< result)
 {
  extract_version(result:result, port:port);
  exit(0);
 }
}


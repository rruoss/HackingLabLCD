# OpenVAS Vulnerability Test
# $Id: iis_frag_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Test Microsoft IIS Source Fragment Disclosure
#
# Authors:
# Pedro Antonio Nieto Feijoo <pedron@cimex.com.cu>
#
# Copyright:
# Copyright (C) 2001 Pedro Antonio Nieto Feijoo
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
tag_summary = "Microsoft IIS 4.0 and 5.0 can be made to disclose
fragments of source code which should otherwise be
inaccessible. This is done by appending +.htr to a
request for a known .asp (or .asa, .ini, etc) file.";

tag_solution = ".htr script mappings should be removed if not required.

- open Internet Services Manager
- right click on the web server and select properties
- select WWW service > Edit > Home Directory > Configuration
- remove the application mappings reference to .htr

If .htr functionality is required, install the relevant patches 
from Microsoft (MS01-004)";


# Test Microsoft IIS 4.0/5.0 Source Fragment Disclosure Vulnerability

if(description)
{
 script_id(10680);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1193, 1488);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2000-0457", "CVE-2000-0630");

 name = "Test Microsoft IIS Source Fragment Disclosure";

 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 summary = "Test Microsoft IIS Source Fragment Disclosure";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 Pedro Antonio Nieto Feijoo");
 family = "Remote file access";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS01-004.mspx");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

BaseURL="";        # root of the default app

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);
if(banner !~ "Microsoft-IIS/[45]\.")exit(0);

if(get_port_state(port))
{
  soc=http_open_socket(port);
  if (soc)
  {
    req = http_get(item:"/", port:port);
    send(socket:soc,data:req);
    data = http_recv(socket:soc);

    if ( ! data ) exit(0);
    if(egrep(pattern:"^HTTP.* 40[123] .*", string:data) )exit(0); # if default response is Access Forbidden, a false positive will result
    if("WWW-Authenticate" >< data)exit(0); 
    http_close_socket(soc);

    # Looking for the 302 Object Moved ...
    if (data)
    {
      if ("301" >< data || "302" >< data || "303" >< data)
      {
        # Looking for Location of the default webapp
        tmpBaseURL=egrep(pattern:"Location:*",string:data);

        # Parsing Path
        if (tmpBaseURL)
        {
          tmpBaseURL=tmpBaseURL-"Location: ";
          len=strlen(tmpBaseURL);
          strURL="";

          for (j=0;j<len;j=j+1)
          {
            strURL = string(strURL,tmpBaseURL[j]);
            if (tmpBaseURL[j]=="/")
            {
              BaseURL=string(BaseURL,strURL);
              strURL="";
            }
          }
        }
      }
    }

    if (BaseURL=="") BaseURL="/";

    # We're going to attack!
    soc = http_open_socket(port);

    if (soc)
    {
      req = http_get(item:BaseURL, port:port);
      send(socket:soc, data:req);
      data = http_recv(socket:soc);
      http_close_socket(soc);
      if ( ! data ) exit(0);
      if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 40[13] .*", string:data))exit(0);
      if("WWW-Authenticate:" >< data)exit(0);
      
      soc = http_open_socket(port);
      if(!soc)exit(0);

      req = http_get(item:string(BaseURL,"global.asa+.htr"), port:port);
      send(socket:soc, data:req);
      code = recv_line(socket:soc, length:1024);
      if(!strlen(code))exit(0);
      data = http_recv(socket:soc);
      http_close_socket(soc);
      
      

      # HTTP/1.x 200 - Command was executed
      if (" 200 " >< code)
      {
        if ("RUNAT"><data)
        {
          security_hole(port:port, protocol:"tcp",
                        data:string("We could disclosure the source 
code of the ", string(BaseURL,"global.asa"), " on the remote web 
server.
This allows an attacker to gain access to fragments of source 
code of the remote applications.

Solution: .htr script mappings should be removed if not required.

- open Internet Services Manager
- right click on the web server and select properties
- select WWW service > Edit > Home Directory > Configuration
- remove the application mappings reference to .htr

If .htr functionality is required, install the relevant patches
from Microsoft (MS01-004)") );
        }
      }
      # HTTP/1.x 401 - Access denied
      # HTTP/1.x 403 - Access forbidden
      else
      {
        if (" 401 " >< code)
        {
          security_warning(port:port, protocol:"tcp",
                           data:"
It seems that it's possible to disclose fragments
of source code of your web applications which
should otherwise be inaccessible. This is done by
appending +.htr to a request for a known .asp (or
.asa, .ini, etc) file.

Solution: .htr script mappings should be removed if not required.

- open Internet Services Manager
- right click on the web server and select properties
- select WWW service > Edit > Home Directory > Configuration
- remove the application mappings reference to .htr

If .htr functionality is required, install the relevant patches 
from Microsoft (MS01-004)
See also: http://www.microsoft.com/technet/security/bulletin/MS01-004.mspx");
        }
        else
        {
          if (" 403 " >< code)
          {
            security_warning(port:port, protocol:"tcp",
                             data:"
It seems that it's possible to disclose fragments
of source code of your web applications which
should otherwise be inaccessible. This is done by
appending +.htr to a request for a known .asp (or
.asa, .ini, etc) file.

Solution: .htr script mappings should be removed if not required.

- open Internet Services Manager
- right click on the web server and select properties
- select WWW service > Edit > Home Directory > Configuration
- remove the application mappings reference to .htr

If .htr functionality is required, install the relevant patches 
from Microsoft (MS01-004)
See also: http://www.microsoft.com/technet/security/bulletin/MS01-004.mspx");
          }
        }
      }
    }
  }
}

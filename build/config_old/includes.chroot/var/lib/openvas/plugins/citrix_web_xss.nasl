# OpenVAS Vulnerability Test
# $Id: citrix_web_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Citrix Web Interface XSS
#
# Authors:
# Michael J. Richardson <michael.richardson@protiviti.com>
#
# Copyright:
# Copyright (C) 2003 Michael J. Richardson
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
tag_summary = "The remote server is running a Citrix Web Interface server that is vulnerable to cross site scripting.  When a user fails to authenticate, the Citrix Web Interface includes the error message text in the URL.  The error message can be tampered with to perform a XSS attack.";

tag_solution = "Upgrade to Citrix Web Interface 2.1 or newer.";

if(description)
{
  script_id(12301);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1157");
  script_bugtraq_id(8939);
  script_xref(name:"OSVDB", value:"2762");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");

  name = "Citrix Web Interface XSS";

  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;


 script_description(desc);
 
 summary = "Checks for Citrix Web Interface Cross Site Scripting Vulnerability";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2003 Michael J. Richardson");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "-");
  script_xref(name : "URL" , value : "-");
  script_xref(name : "URL" , value : "-");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))
  exit(0);

if(get_kb_item(string("www/", port, "/generic_xss"))) 
  exit(0);


function check(url)
  {
    req = http_get(item:string(url, "/login.asp?NFuse_LogoutId=&NFuse_MessageType=Error&NFuse_Message=<SCRIPT>alert('Ritchie')</SCRIPT>&ClientDetection=ON"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if ( res == NULL ) 
      exit(0);

    if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res) && "<SCRIPT>alert('Ritchie')</SCRIPT>" >< res)
      {
        security_warning(port);
        exit(0);
      }
 
  }

check(url:"/citrix/nfuse/default");
check(url:"/citrix/MetaframeXP/default");

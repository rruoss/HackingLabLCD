# OpenVAS Vulnerability Test
# $Id: tomcat_srcjsp_malformed_request.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Apache Tomcat source.jsp malformed request information disclosure
#
# Authors:
# David Kyger <david_kyger@symantec.com>
# Updated By: Antu Sanadi <santu@secpod> on 2010-07-06
# Updated CVE, CVSS Base and Risk Factor 
#
# Copyright:
# Copyright (C) 2004 David Kyger
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
tag_summary = "The source.jsp file, distributed with Apache Tomcat server, will
disclose information when passed a malformed request. As a result,
information such as the web root path and directory listings could
be obtained.

Example: http://target/examples/jsp/source.jsp?? - reveals the web root
         http://target/examples/jsp/source.jsp?/jsp/ - reveals the contents of the jsp directory";

tag_solution = "Remove default files from the web server";

if(description)
{
  script_id(12123);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2000-1210");
  script_bugtraq_id(4876);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");

 name = "Apache Tomcat source.jsp malformed request information disclosure";
 script_name(name);
 
 desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

 script_description(desc);
 
 summary = "Checks for the Tomcat source.jsp malformed request vulnerability";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2004 David Kyger");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/4876");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

warning = string("
The source.jsp file, distributed with Apache Tomcat server, will
disclose information when passed a malformed request. As a result,
information such as the web root path and directory listings could
be obtained.

The following information was obtained via a malformed request to
the web server:");

port = get_http_port(default:80);

if(get_port_state(port))
 {
  pat1 = "Directory Listing";
  pat2 = "file";

  fl[0] = "/examples/jsp/source.jsp??";
  fl[1] = "/examples/jsp/source.jsp?/jsp/";

  for(i=0;fl[i];i=i+1) {
    req = http_get(item:fl[i], port:port);
    buf = http_keepalive_send_recv(port:port, data:req);
    if ( buf == NULL ) exit(0);
    if ( pat1 >< buf && pat2 >< buf) {
     warning += string("\n", buf);
     warning += string("\nSolution: Remove default files from the web server");
     warning += string("\nSee also: http://www.securityfocus.com/bid/4876");
	security_warning(port:port, data:warning);
	exit(0);
     }
    }
}


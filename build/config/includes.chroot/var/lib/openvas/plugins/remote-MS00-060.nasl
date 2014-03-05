# OpenVAS Vulnerability Test
# $Id: remote-MS00-060.nasl 15 2013-10-27 12:49:54Z jan $
# Description: 
# Microsoft Security Bulletin (MS00-060)
# 'IIS Cross-Site Scripting' Vulnerabilities 
#
# Affected Software: 
# Microsoft Internet Information Server 4.0 
# Microsoft Internet Information Server 5.0 
#
# remote-MS00-060.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later,
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
tag_summary = "Vulnerabilities in IIS 4.0 and 5.0 do not properly protect against cross-site scripting (CSS) attacks. 
They allow a malicious web site operator to embed scripts in a link to a trusted site, 
which are returned without quoting in an error message back to the client. 
The client then executes those scripts in the same context as the trusted site.";

tag_solution = "Microsoft has released a patch to correct these issues,
Download locations for this patch:

Internet Information Server 4.0:
http://www.microsoft.com/downloads/details.aspx?FamilyId=FE95D9FC-D769-43F3-8376-FAA1D2ABC4F3&displaylang=en 
 
Internet Information Server 5.0:
http://www.microsoft.com/downloads/details.aspx?FamilyId=31734888-9C17-43F1-BFD9-FDA8FEAF6D68&displaylang=en";


if(description)
{
script_id(101000);
script_version("$Revision: 15 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2009-03-08 14:50:37 +0100 (Sun, 08 Mar 2009)");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"risk_factor", value:"High");
script_cve_id("CVE-2000-0746", "CVE-2000-0746", "CVE-2000-1104");
script_bugtraq_id(1594, 1595);
name = "Microsoft MS00-060 security check";
script_name(name);
 
desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;


script_description(desc);
 
summary = "Microsoft IIS 4.0 and 5.0 are prone to Cross Site Scripting (XSS) vulnerabilities";
 
script_summary(summary);
 
script_category(ACT_ATTACK);
 
script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
family = "Windows : Microsoft Bulletins";
script_family(family);
script_require_ports("Services/www");
 
if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
}
exit(0);
}


#
# The script code starts here
#

include("http_func.inc");


iis = get_kb_list("Services/www");

# build the malicious request
page = '/_vti_bin/shtml.dll/<script>alert(1)</script>';

foreach port (iis)
{
	soc = open_sock_tcp(port);
	if(!soc)continue;
		
		req = http_get(item:page, port:port);
		send(socket:soc, data: req);
		
		reply = recv(socket:soc, length:4096);
		close(soc);

		if(reply)
		{
			if(("Microsoft-IIS" >< reply ) && (egrep(pattern:"HTTP/1.[01] 200", string:reply, icase:TRUE)) && ("<script>(1)</script>" >< reply)) 
				security_hole(port);
		}
}

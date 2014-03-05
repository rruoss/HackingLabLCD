# OpenVAS Vulnerability Test
# $Id: remote-ApacheOfbiz-htmlInjection.nasl 15 2013-10-27 12:49:54Z jan $
# Description: the script test the following vulnerabilities issues
# OFBiz Search_String Parameter HTML Injection Vulnerability (BID 21702)
# OFBiz Unspecified HTML Injection Vulnerability (BID 21529)
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
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
tag_summary = "The running Apache OFBiz is prone to the following security issue
OFBiz Search_String Parameter HTML Injection Vulnerability
OFBiz Unspecified HTML Injection Vulnerability";

tag_solution = "Download the latest release form Apache Software Foundation (OFBiz) website";



if(description)
{
script_id(101020);
script_version("$Revision: 15 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2009-04-22 20:27:36 +0200 (Wed, 22 Apr 2009)");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_tag(name:"risk_factor", value:"High");
script_cve_id("CVE-2006-6589","CVE-2006-6587");
script_bugtraq_id(21702, 21529);
name = "Apache Open For Business HTML injection vulnerability";
script_name(name);
 
desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;
script_description(desc); 

summary = "Apache Open For Business XSS security check";

script_summary(summary);

script_category(ACT_ATTACK);

script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
family = "Web application abuses";
script_family(family);
script_dependencies("find_service.nasl","remote-detect-ApacheOfbiz.nasl");
script_require_ports("Services/www");
script_require_keys("ApacheOFBiz/installed","ApacheOFBiz/version", "ApacheOFBiz/port");

if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
}
exit(0);

}

#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("ApacheOFBiz/port");
report = '';

if(!get_kb_item("ApacheOFBiz/installed") || !get_kb_item("ApacheOFBiz/version") || !port)
        exit(0);

else {
	version = get_kb_item("ApacheOFBiz/version");

	if(revcomp(a:version, b:"3.0.0") <= 0){
		# report:
		# OFBiz Search_String Parameter HTML Injection Vulnerability
		# OFBiz Unspecified HTML Injection Vulnerability 
		report += "The current Apache OFBiz version " + version + " is affected by a Search_String Parameter HTML injection vulnerability";
	}
}

if(report)
	security_hole(port:port, data:report);

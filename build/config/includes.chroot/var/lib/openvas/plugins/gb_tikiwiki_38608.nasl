###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tikiwiki_38608.nasl 14 2013-10-27 12:33:37Z jan $
#
# TikiWiki Versions Prior to 4.2 Multiple Unspecified Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
tag_summary = "TikiWiki is prone to multiple unspecified vulnerabilities, including:

- An unspecified SQL-injection vulnerability
- An unspecified authentication-bypass vulnerability
- An unspecified vulnerability

Exploiting these issues could allow an attacker to compromise the
application, access or modify data, exploit latent vulnerabilities in
the underlying database, and gain unauthorized access to the affected
application. Other attacks are also possible.

Versions prior to TikiWiki 4.2 are vulnerable.";

tag_solution = "The vendor has released an advisory and fixes. Please see the
references for details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100537";
CPE = "cpe:/a:tikiwiki:tikiwiki";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-15 19:33:39 +0100 (Mon, 15 Mar 2010)");
 script_bugtraq_id(38608);
 script_cve_id("CVE-2010-1135", "CVE-2010-1134", "CVE-2010-1133", "CVE-2010-1136");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("TikiWiki Versions Prior to 4.2 Multiple Unspecified Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 script_summary("Determine if TikiWiki version is < 4.2");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_tikiwiki_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("TikiWiki/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38608");
 script_xref(name : "URL" , value : "http://tikiwiki.svn.sourceforge.net/viewvc/tikiwiki?view=rev&amp;revision=24734");
 script_xref(name : "URL" , value : "http://tikiwiki.svn.sourceforge.net/viewvc/tikiwiki?view=rev&amp;revision=25046");
 script_xref(name : "URL" , value : "http://tikiwiki.svn.sourceforge.net/viewvc/tikiwiki?view=rev&amp;revision=25424");
 script_xref(name : "URL" , value : "http://tikiwiki.svn.sourceforge.net/viewvc/tikiwiki?view=rev&amp;revision=25435");
 script_xref(name : "URL" , value : "http://info.tikiwiki.org/article86-Tiki-Announces-3-5-and-4-2-Releases");
 script_xref(name : "URL" , value : "http://info.tikiwiki.org/tiki-index.php?page=homepage");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "4.2")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);

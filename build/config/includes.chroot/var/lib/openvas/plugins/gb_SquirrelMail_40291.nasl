###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_SquirrelMail_40291.nasl 14 2013-10-27 12:33:37Z jan $
#
# SquirrelMail 'mail_fetch' Remote Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
tag_summary = "SquirrelMail is prone to a remote information-disclosure
vulnerability.

Attackers can exploit this issue to obtain potentially sensitive
information that may lead to further attacks.

This issue affects SquirrelMail 1.4.x versions.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100688);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-22 12:10:21 +0200 (Tue, 22 Jun 2010)");
 script_bugtraq_id(40291);
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_cve_id("CVE-2010-1637");

 script_name("SquirrelMail 'mail_fetch' Remote Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40291");
 script_xref(name : "URL" , value : "http://permalink.gmane.org/gmane.comp.security.oss.general/2935");
 script_xref(name : "URL" , value : "http://permalink.gmane.org/gmane.comp.security.oss.general/3064");
 script_xref(name : "URL" , value : "http://permalink.gmane.org/gmane.comp.security.oss.general/2936");
 script_xref(name : "URL" , value : "http://conference.hitb.org/hitbsecconf2010dxb/materials/D1%20-%20Laurent%20Oudot%20-%20Improving%20the%20Stealthiness%20of%20Web%20Hacking.pdf#page=69");
 script_xref(name : "URL" , value : "http://www.squirrelmail.org");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if SquirrelMail version is < 1.4.21/1.5.2");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("squirrelmail_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"squirrelmail")) {

  if(version_in_range(version: vers, test_version: "1.4", test_version2: "1.4.20") ||
     version_in_range(version: vers, test_version: "1.5", test_version2: "1.5.1")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);

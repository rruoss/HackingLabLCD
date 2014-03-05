###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_znc_42314.nasl 14 2013-10-27 12:33:37Z jan $
#
# ZNC Multiple Denial Of Service Vulnerabilities
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
tag_summary = "ZNC is prone to a multiple remote denial-of-service vulnerabilities.

An attacker may exploit these issues to crash the application,
resulting in denial-of-service conditions.

ZNC 0.092 is vulnerable; other versions may also be affected.";

tag_solution = "Fixes are available in the SVN repository. Please see the references
for details.";

if (description)
{
 script_id(100758);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-08-13 12:44:16 +0200 (Fri, 13 Aug 2010)");
 script_bugtraq_id(42314);
 script_cve_id("CVE-2010-2812","CVE-2010-2934");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_name("ZNC Multiple Denial Of Service Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed znc version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("znc_detect.nasl");
 script_require_ports("Services/irc", 6667);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42314");
 script_xref(name : "URL" , value : "http://en.znc.in/wiki/ZNC");
 script_xref(name : "URL" , value : "http://znc.svn.sourceforge.net/viewvc/znc?view=revision&amp;revision=2093");
 script_xref(name : "URL" , value : "http://znc.svn.sourceforge.net/viewvc/znc?view=revision&amp;revision=2095");
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/irc");
if (!port) port = 6667;
if(!get_port_state(port))exit(0);

if(!vers = get_kb_item(string("znc/", port, "/version")))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "0.092")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);


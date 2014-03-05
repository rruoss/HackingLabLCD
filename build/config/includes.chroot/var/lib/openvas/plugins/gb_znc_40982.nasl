###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_znc_40982.nasl 14 2013-10-27 12:33:37Z jan $
#
# ZNC NULL Pointer Dereference Denial Of Service Vulnerability
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
tag_summary = "ZNC is prone to a remote denial-of-service vulnerability caused by a
NULL-pointer dereference.

An attacker may exploit this issue to crash the application, resulting
in denial-of-service conditions. Given the nature of this issue, the
attacker may also be able to run arbitrary code, but this has not been
confirmed.

The issue affects ZNC 0.090; other versions may also be affected.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100683);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-21 20:36:15 +0200 (Mon, 21 Jun 2010)");
 script_tag(name:"cvss_base", value:"3.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2010-2448");
 script_bugtraq_id(40982);

 script_name("ZNC NULL Pointer Dereference Denial Of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if znc version is 0.090");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("znc_detect.nasl");
 script_require_ports("Services/irc", 6667);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40982");
 script_xref(name : "URL" , value : "http://en.znc.in/wiki/ZNC");
 script_xref(name : "URL" , value : "http://znc.svn.sourceforge.net/viewvc/znc?revision=2026&amp;view=revision");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=603915");
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/irc");
if (!port) port = 6667;
if(!get_port_state(port))exit(0);

if(!vers = get_kb_item(string("znc/", port, "/version")))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "0.090")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);

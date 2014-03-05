###############################################################################
# OpenVAS Vulnerability Test
# $Id: znc_35757.nasl 15 2013-10-27 12:49:54Z jan $
#
# ZNC File Upload Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "ZNC is prone to a directory-traversal vulnerability because it fails
to sufficiently sanitize user-supplied input.

Exploiting this issue can allow an authenticated attacker to upload
and overwrite files on the affected computer. Successful exploits will
lead to other attacks.

Versions prior to ZNC 0.072 are vulnerable,";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100244);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)");
 script_bugtraq_id(35757);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("ZNC File Upload Directory Traversal Vulnerability");

desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 script_summary("Determine if ZNC Version < 0.072");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("znc_detect.nasl");
 script_require_ports("Services/irc", 6667);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/35757");
 script_xref(name : "URL" , value : "http://znc.svn.sourceforge.net/viewvc/znc?view=rev&amp;sortby=rev&amp;sortdir=down&amp;revision=1570");
 script_xref(name : "URL" , value : "http://en.znc.in/wiki/ZNC");
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/irc");
if (!port) port = 6667;
if(!get_port_state(port))exit(0);

if(!vers = get_kb_item(string("znc/", port, "/version")))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "0.072")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: eggdrop_24070.nasl 15 2013-10-27 12:49:54Z jan $
#
# Eggdrop Server Module Message Handling Remote Buffer Overflow
# Vulnerability
#
# Authors
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
tag_summary = "Eggdrop Server Module is prone to a remote buffer-overflow
  vulnerability because the application fails to bounds-check
  user-supplied data before copying it into an insufficiently sized
  buffer.

  An attacker can exploit this issue to execute arbitrary code within
  the context of the affected application. Failed exploit attempts
  will result in a denial-of-service condition.

  Eggdrop 1.6.18 is known to be vulnerable; other versions may be
  affected as well.";

tag_solution = "The vendor has released an update. Please see
  http://www.eggheads.org/ for more information.";

if (description)
{
 script_id(100228);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-07-08 19:01:22 +0200 (Wed, 08 Jul 2009)");
 script_bugtraq_id(24070);
 script_cve_id("CVE-2007-2807");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("Eggdrop Server Module Message Handling Remote Buffer Overflow Vulnerability");
 desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_summary("Determine if Eggdrop Version < 1.6.18");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("eggdrop_detect.nasl");
 script_require_ports("Services/eggdrop",3333);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/24070");
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/eggdrop");

if(!port) {
   port = 3333;
}  

if(!get_port_state(port))exit(0);
if(!version = get_kb_item(string("eggdrop/version/", port)))exit(0);

if(!isnull(version) && version >!< "unknown") {

  if(version_is_less(version: version, test_version: "1.6.18")) {
      security_hole(port:port);
      exit(0);
  }  

} 

exit(0);

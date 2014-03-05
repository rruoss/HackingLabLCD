###############################################################################
# OpenVAS Vulnerability Test
# $Id: eggdrop_34985.nasl 15 2013-10-27 12:49:54Z jan $
#
# Cacti 'data_input.php' Cross Site Scripting Vulnerability
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
tag_summary = "Eggdrop is prone to a remote denial-of-service vulnerability because
  it fails to adequately validate user-supplied input.

  An attacker may exploit this issue to crash the application,
  resulting in a denial-of-service condition.

  This issue is related to the vulnerability described in BID 24070
  (Eggdrop Server Module Message Handling Remote Buffer Overflow
  Vulnerability).

  Versions prior to Eggdrop 1.6.19+ctcpfix are vulnerable.";

tag_solution = "The vendor has released an update. Please see
  http://www.eggheads.org/ for more information.";

if (description)
{
 script_id(100207);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-16 14:32:16 +0200 (Sat, 16 May 2009)");
 script_cve_id("CVE-2009-1789");
 script_bugtraq_id(34985);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Eggdrop 'ctcpbuf' Remote Denial Of Service Vulnerability");
 desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_summary("Determine if Eggdrop Version < 1.6.19+ctcpfix");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("eggdrop_detect.nasl");
 script_require_ports("Services/eggdrop",3333);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34985");
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

  if(version_is_less(version: version, test_version: "1.6.19+ctcpfix")) {
      security_warning(port:port);
      exit(0);
  }  

} 

exit(0);

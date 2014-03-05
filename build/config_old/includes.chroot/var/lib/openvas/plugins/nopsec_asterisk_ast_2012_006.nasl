##############################################################################
# OpenVAS Vulnerability Test
# $Id: nopsec_asterisk_ast_2012_006.nasl 110018 
#2012-06-19 11:43:12 +0100 (Tue, 19 Jun 2012) $
#
# SIP channel driver in Asterisk suffers remote crash vulnerability
#
# Authors:
# Songhan Yu <syu@nopsec.com>
#
# Copyright:
# Copyright NopSec Inc. 2012, http://www.nopsec.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "chan_sip.c in the SIP channel driver in Asterisk Open Source 1.8.x before 1.8.11.1 and 10.x before 10.3.1 and Asterisk Business Edition C.3.x before C.3.7.4, when the trustrpid option is enabled, alLows remote authenticated users to cause a denial of service (daemon crash) by sending a SIP UPDATE message that triggers a connected-line update attempt without an associated channel.
Recommendation:
Upgrate to 1.8.11.1 / 10.3.1 / C.3.7.4 or versions after.";


if (description)
{
  script_id(110018);
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-06-19 11:43:12 +0100 (Tue, 19 Jun 2012)");

  script_cve_id("CVE-2012-2416");
  script_bugtraq_id(53205);
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"risk_factor", value:"High");
  script_name("SIP channel driver in Asterisk suffers remote crash vulnerability");
  script_summary("Check the version in SIP banner.");

  desc = "
  Summary:
  " + tag_summary;

 script_description(desc);
 script_category(ACT_DENIAL);
 script_family("Denial of Service");
 script_copyright("Copyright NopSec Inc. 2012");
 script_dependencies("secpod_asterisk_detect.nasl");
 script_require_keys("Services/udp/sip");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
 exit(0);
}
include("version_func.inc");

port = get_kb_item("Services/udp/sip");
if(!port || !get_udp_port_state(port))exit(0);

version_asterisk = get_kb_item("Asterisk-PBX/Ver");
if(version_asterisk)
{
  if(version_in_range(version:version_asterisk, test_version:"1.8",  test_version2:"1.8.11.1")  ||
   version_in_range(version:version_asterisk, test_version:"10",    test_version2:"10.3.1")   ||
   (version_asterisk =~ "^C\.3([^0-9]|$)"))
   {
     security_hole(port:port, proto:"udp");
     exit(0);
   }
}
exit(0);


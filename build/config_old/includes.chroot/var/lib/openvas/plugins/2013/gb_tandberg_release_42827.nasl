###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tandberg_release_42827.nasl 11 2013-10-27 10:12:02Z jan $
#
# TANDBERG MXP Series Video Conferencing Device Remote Denial Of Service Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103788";
CPE = "cpe:/h:tandberg";

tag_insight = "The devices are exposed to a remote denial of service issue because
they fail to properly validate user-supplied data.";

tag_impact = "A successful exploit will cause the device to crash, denying service
to legitimate users.";

tag_affected = "TANDBERG MXP Series devices with version F8.2 is vulnerable; other
versions may also be affected.";

tag_summary = "TANDBERG MXP Series devices are prone to a remote denial-of-service
vulnerability.";

tag_solution = "Updates are available. Please see the references for more details.";
tag_vuldetect = "Check if Codec Release is <= F8.2 ";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(42827);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

 script_name("TANDBERG MXP Series Video Conferencing Device Remote Denial Of Service Vulnerability");

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

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42827");
 script_xref(name:"URL", value:"http://www.tandberg.com/products/mxp_user_guide.jsp");
 script_xref(name:"URL", value:"ftp://ftp.tandberg.com/pub/software/endpoints/mxp/TANDBERG%20MXP%20Endpoints%20Software%20Release%20Notes%20%28F9%29.pdf");
 
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-09-12 13:33:18 +0200 (Thu, 12 Sep 2013)");
 script_description(desc);
 script_summary("Determine if Codec Release is <= F8.2");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_tandberg_devices_detect.nasl");
 script_require_ports("Services/telnet", 23);
 script_require_keys("tandberg_codec_release");

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

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(vers = get_kb_item("tandberg_codec_release")) {

  version = eregmatch(pattern:"F([0-9.]+)", string:vers);
  if(isnull(version[1]))exit(0);

  if(version_is_less_equal(version: version[1], test_version: "8.2")) {
      security_hole(port:port);
      exit(0);
  }
}
  
exit(0);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_57841.nasl 11 2013-10-27 10:12:02Z jan $
#
# Cisco Nexus 7000 Series Switches  Remote Denial of Service Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103802";
CPE = "cpe:/o:cisco:nx-os";

tag_insight = "This issue is being tracked by Cisco Bug ID CSCud15673.";

tag_impact = "Successfully exploiting this issue allows remote attackers to cause
denial-of-service conditions.";

tag_affected = "Cisco Nexus 7000 Series running on NX-OS.";

tag_summary = "Cisco Nexus 7000 Series switches running on NX-OS are prone to a
remote denial-of-service vulnerability.";

tag_solution = "Ask the Vendor for an update.";
tag_vuldetect = "Check the version from SNMP sysdesc";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(57841);
 script_cve_id("CVE-2013-1122");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_version ("$Revision: 11 $");

 script_name("Cisco Nexus 7000 Series Switches  Remote Denial of Service Vulnerability");

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

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57841");
 script_xref(name:"URL", value:"http://www.cisco.com/");
 script_xref(name:"URL", value:"http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1122");
 
 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-10-10 12:14:44 +0200 (Thu, 10 Oct 2013)");
 script_description(desc);
 script_summary("Chek the installed NX-OS version");
 script_category(ACT_GATHER_INFO);
 script_family("CISCO");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_cisco_nx_os_detect.nasl");
 script_require_keys("cisco/nx_os/version","cisco/nx_os/model");

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

if(!nx_model = get_kb_item("cisco/nx_os/model"))exit(0);
if(!nx_ver = get_kb_item("cisco/nx_os/version"))exit(0);

if('Nexus7000' >!< nx_model)exit(0);

affected = make_list(
                     "4.2(1)sv1(4a)",
                     "4.2(1)sv1(4)",
                     "4.0(4)sv1(1)",
                     "4.0(4)sv1(2)",
                     "4.2(1)sv1(5.1)",
                     "4.0(4)sv1(3d)",
                     "5.1(3)n1(1a)",
                     "5.0(3)n2(2b)",
                     "5.0(3)n2(2a)",
                     "4.0(4)sv1(3)",
                     "4.0(4)sv1(3a)",
                     "4.0(4)sv1(3b)",
                     "4.0(4)sv1(3c)",
                     "4.0",
                     "5.0(2)n2(1)",
                     "5.0(2)n2(1a)",
                     "5.0(3)n1(1b)",
                     "5.0(2)n1(1)",
                     "5.0(3)n2(1)",
                     "5.0(3)n2(2)",
                     "5.1(3)n1(1)",
                     "5.0(3)n1(1c)",
                     "4.0(1a)n2(1a)",
                     "4.1(3)n1(1)",
                     "4.0(1a)n1(1a)",
                     "4.0(1a)n2(1)",
                     "5.0(3)n1(1)",
                     "5.0(3)n1(1a)",
                     "4.1(3)n1(1a)",
                     "4.2(1)n2(1a)",
                     "4.2",
                     "4.1(3)n2(1a)",
                     "5.0",
                     "4.1(3)n2(1)",
                     "4.2(1)n2(1)",
                     "4.2(1)n1(1)",
                     "4.0(0)n1(1a)",
                     "4.0(0)n1(2)",
                     "5.2",
                     "4.0(1a)n1(1)",
                     "5.1",
                     "4.0(0)n1(2a)",
                     "4.2(1)",
                     "4.2(2)",
                     "5.0(3)",
                     "5.0(2a)",
                     "4.2(4)",
                     "4.2.(2a)",
                     "4.2(6)",
                     "4.2(3)",
                     "4.1.(5)",
                     "4.1.(4)",
                     "4.1.(3)",
                     "4.1.(2)",
                     "4.2(8)",
                     "5.1(2)",
                     "5.0(2)",
                     "5.2(3)",
                     "5.1(4)",
                     "5.1(3)",
                     "5.1(1a)",
                     "5.1(1)",
                     "5.0(5)",
                     "5.2(3a)",
                     "5.2(1)",
                     "5.1(6)",
                     "5.1(5)",
                     "6.0(1)",
                     "6.0(2)",
                     "6.1");

foreach affected_nx_ver (affected) {
  if(nx_ver == affected_nx_ver) {
    security_hole(0);
    exit(0);
  }
}

exit(99);
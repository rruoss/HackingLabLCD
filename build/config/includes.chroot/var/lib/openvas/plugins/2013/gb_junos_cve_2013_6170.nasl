###############################################################################
# OpenVAS Vulnerability Test
# $Id
#
# Junos PIM Join Flooding Denial of Service Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103949";
SCRIPT_DESC = "Junos PIM Join Flooding Denial of Service Vulnerability";

tag_insight = "Receipt of a large number of crafted IPv4 or IPv6 PIM join
messages in a Next-Generation Multicast VPN (NGEN MVPN) environment can trigger
the RPD routing daemon to crash.";

tag_impact = "Once a large amount of these PIM joins are received by the
router, RPD crashes and restarts. ";

tag_affected = "Junos OS 10.0 or later but only applies to PIM in an NGEN MVPN
environment.";

tag_summary = "A large number of crafted PIM join messages can crash the RPD
routing daemon.";

tag_solution = "New builds of Junos OS software are available from Juniper. As
a workaround ACLs or firewall filters to limit PIM access to the router only
from trusted hosts.";

tag_vuldetect = "Check the OS build.";

if (description)
{
  script_oid(SCRIPT_OID);
  script_bugtraq_id(62973);
  script_cve_id("CVE-2013-6170");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_version ("$Revision: 72 $");

  script_name(SCRIPT_DESC);

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

  script_xref(name:"URL", value:"http://kb.juniper.net/InfoCenter/index?page=content&amp;id=JSA10548");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62973");
  script_xref(name:"URL", value:"http://secunia.com/advisories/55216");
  
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-11-21 18:10:44 +0100 (Thu, 21 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-10-28 12:53:03 +0700 (Mon, 28 Oct 2013)");
  script_description(desc);
  script_summary("Junos CVE-2013-6170");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_junos_get_version.nasl","gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Build", "Junos/Version");

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

include("version_func.inc");

version = get_kb_item("Junos/Version");
if (!version)
  exit(0);

build = get_kb_item("Junos/Build");
if (!build)
  exit(0);

desc += "Version/Build-Date:
" + version + " / " + build;

build2check = str_replace(string:build, find:"-", replace:"");

if (revcomp(a:build2check, b:"20120927") >= 0) {
  exit(99);
}

if (revcomp(a:version, b:"10.0S28") < 0) {
  security_hole(port:port, data:desc);
  exit(0);
}

if (version =~ "^10") {
  if (revcomp(a:version, b:"10.4R7") < 0) {
    security_hole(port:port, data:desc);
    exit(0);
  }
}

if (version =~ "^11") {
  if (revcomp(a:version, b:"11.1R5") < 0) {
    security_hole(port:port, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"11.2R2") < 0) &&
             (revcomp(a:version, b:"11.2") >= 0)) {
      security_hole(port:port, data:desc);
      exit(0);
  } else if ((revcomp(a:version, b:"11.4R1") < 0) &&
              revcomp(a:version, b:"11.4") >= 0) {
      security_hole(port:port, data:desc);
      exit(0);
  }
} 

exit(99);

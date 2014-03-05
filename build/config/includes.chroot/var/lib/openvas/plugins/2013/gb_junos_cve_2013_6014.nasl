###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_cve_2013_6014.nasl 70 2013-11-21 03:20:24Z ckuerste $
#
# Junos Security issue with Proxy ARP enabled on unnumbered interface
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103952";
SCRIPT_DESC = "Junos Security Issue whith Proxy ARP Enabled";

tag_insight = "When Proxy ARP is enabled on an unnumbered interface, it allows
remote attackers to perform ARP poisoning attacks and possibly obtain sensitive
information via a crafted ARP message.";

tag_impact = "An attacker can either create a denial of service attack or
might obtain some sensitive information.";

tag_affected = "Plattforms running Junos OS 10.4, 11.4, 11.4X27, 12.1, 12.1X44,
12.1X45, 12.2, 12.3, or 13.1";

tag_summary = "Information disclosure or denial of service vulnerability when
Proxy ARP is enabled on a unnumbered interface.";

tag_solution = "New builds of Junos OS software are available from Juniper.";

tag_vuldetect = "Check the OS build.";

if (description)
{
  script_oid(SCRIPT_OID);
  script_bugtraq_id(63391);
  script_cve_id("CVE-2013-6014");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_version ("$Revision: 70 $");

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

  script_xref(name:"URL", value:"http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10595");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63391");
  
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-11-21 04:20:24 +0100 (Thu, 21 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-11-18 12:34:58 +0700 (Mon, 18 Nov 2013)");
  script_description(desc);
  script_summary("Junos CVE-2013-6014");
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

if (revcomp(a:build2check, b:"20130918") >= 0) {
  exit(99);
}

if (revcomp(a:version, b:"10.4S15") < 0) {
  security_hole(port:port, data:desc);
  exit(0);
}

if (version =~ "^11") {
  if (revcomp(a:version, b:"11.4R9") < 0) {
    security_hole(port:port, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"11.4X27.44") < 0) &&
             (revcomp(a:version, b:"11.4X27") >= 0)) {
      security_hole(port:port, data:desc);
      exit(0);
  }
}

if (version =~ "^12") {
  if (revcomp(a:version, b:"12.1R7") < 0) {
    security_hole(port:port, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"12.1X44-D20") < 0) &&
             (revcomp(a:version, b:"12.1X44") >= 0)) {
      security_hole(port:port, data:desc);
      exit(0);
  } else if ((revcomp(a:version, b:"12.1X45-D15") < 0) &&
             (revcomp(a:version, b:"12.1X45") >= 0)) {
      security_hole(port:port, data:desc);
      exit(0);
  } else if ((revcomp(a:version, b:"12.2R6") < 0) &&
             (revcomp(a:version, b:"12.2") >= 0)) {
      security_hole(port:port, data:desc);
      exit(0);
  } else if ((revcomp(a:version, b:"12.3R3") < 0) &&
             (revcomp(a:version, b:"12.3") >= 0)) {
      security_hole(port:port, data:desc);
      exit(0);
  }
}

if (version =~ "^13") {
  if (revcomp(a:version, b:"13.1R3") < 0) {
    security_hole(port:port, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"13.2R1") < 0) &&
             (revcomp(a:version, b:"13.2") >= 0)) {
    security_hole(port:port, data:desc);
    exit(0);
  }
}

exit(99);


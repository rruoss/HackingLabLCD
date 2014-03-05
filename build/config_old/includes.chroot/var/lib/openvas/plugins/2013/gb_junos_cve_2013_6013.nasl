###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_cve_2013_6013.nasl 76 2013-11-25 04:00:56Z ckuerste $
#
# Junos flowd Buffer Overflow Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103954";
SCRIPT_DESC = "Junos flowd Buffer Overflow Vulnerability";

tag_insight = "Buffer overflow in the flow daemon (flowd) when using telnet
pass-through authentication on the firewall.";

tag_impact = "A remote attacker may be able to execute arbitrary code leading
to a complete compromise of the system.";

tag_affected = "Plattforms running Junos OS 10.4, 11.4, or 12.1X44.";

tag_summary = "A buffer overflow in the flow daemon when using telnet
pass-through authentication might lead to a complete compromise of the system.";

tag_solution = "New builds of Junos OS software are available from Juniper. As
a workaround disable telnet pass-through authentication if not required.";

tag_vuldetect = "Check the OS build.";

if (description)
{
  script_oid(SCRIPT_OID);
  script_bugtraq_id(62962);
  script_cve_id("CVE-2013-6013");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version ("$Revision: 76 $");

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

  script_xref(name:"URL", value:"http://kb.juniper.net/InfoCenter/index?page=content&amp;id=JSA10594");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62962");
  
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-11-25 05:00:56 +0100 (Mon, 25 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-11-22 23:25:39 +0700 (Fri, 22 Nov 2013)");
  script_description(desc);
  script_summary("Junos CVE-2013-6013");
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

if (revcomp(a:build2check, b:"20130711") >= 0) {
  exit(99);
}

if (revcomp(a:version, b:"10.4S14") < 0) {
  security_hole(port:port, data:desc);
  exit(0);
}

if (version =~ "^11") {
  if (revcomp(a:version, b:"11.4R7-S2") < 0) {
    security_hole(port:port, data:desc);
    exit(0);
  }
}

if (version =~ "^12") {
  if ((revcomp(a:version, b:"12.1X44-D15") < 0) &&
      (revcomp(a:version, b:"12.1X44") >= 0)) {
    security_hole(port:port, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"12.1X45-D10") < 0) &&
             (revcomp(a:version, b:"12.1X45") >= 0)) {
      security_hole(port:port, data:desc);
      exit(0);
  }
}

exit(99);

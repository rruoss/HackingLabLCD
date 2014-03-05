##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_evolution_data_server_mult_int_overflow_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Evolution Data Server Multiple Integer Overflow Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes
  through long string that is converted to a base64 representation and
  can cause a client crash via NTLM authentication type 2 packet with a
  length value that exceeds the amount of packet data.";
tag_affected = "Evolution Data Server version 2.24.5 and prior.
  Evolution Data Server version in range 2.25.x to 2.25.92";
tag_insight = "- bug in Camel library while processing NTLM SASL packets.
  - bug in glib library while encoding and decoding Base64 data.";
tag_solution = "Upgrade to latest version 2.26
  http://projects.gnome.org/evolution/download.shtml";
tag_summary = "This host is installed with Evolution Data Server and is prone to
  multiple integer overflow vulnerabilities.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.800254";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-18 14:25:01 +0100 (Wed, 18 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_bugtraq_id(34109, 34100);
  script_cve_id("CVE-2009-0582", "CVE-2009-0587");
  script_name("Evolution Data Server Multiple Integer Overflow Vulnerabilities");
  desc = "

  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34286");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1021845");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2009/03/12/2");
  script_xref(name : "URL" , value : "http://mail.gnome.org/archives/release-team/2009-March/msg00096.html");

  script_description(desc);
  script_summary("Check for the version of Evolution Data Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_evolution_data_server_detect.nasl");
  script_require_keys("Evolution/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

# Grep for vulnerable Evolution versions
ver = get_app_version(cpe:"cpe:/a:gnome:evolution", nvt:SCRIPT_OID);
if(version_in_range(version:ver, test_version:"2.25",
                                 test_version2:"2.25.92") ||
   version_is_less_equal(version:ver, test_version:"2.24.5")){
  security_hole(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firewall_builder_priv_esc_vuln_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# Firewall Builder Privilege Escalation Vulnerability (Linux)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow local users to perform certain actions
  with escalated privileges.
  Impact Level: Application";
tag_affected = "Firewall Builder versions 3.0.4 to 3.0.6 on Linux.";
tag_insight = "The flaw is due to the application generating scripts, which are using
  temporary files in an insecure manner. This can be exploited to overwrite
  arbitrary files via symlink attack.";
tag_solution = "Update to version 3.0.7
  For updates refer to http://www.fwbuilder.org/";
tag_summary = "The host is running Firewall Builder and is prone to Privilege
  Escalation vulnerability.";

if(description)
{
  script_id(800996);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-4664");
  script_bugtraq_id(36468);
  script_name("Firewall Builder Privilege Escalation Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/58247");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36809");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53392");
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-February/035112.html");

  script_description(desc);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_summary("Check through version of Firewall Builder");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_firewall_builder_detect_lin.nasl");
  script_require_keys("FirewallBuilder/Linux/Ver");
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

fwbuildVer = get_kb_item("FirewallBuilder/Linux/Ver");
if(isnull(fwbuildVer)){
  exit(0);
}

#Check for versions 3.0.4 to 3.0.6
if(version_in_range(version:fwbuildVer, test_version:"3.0.4", test_version2:"3.0.6" )){
   security_warning(0);
}

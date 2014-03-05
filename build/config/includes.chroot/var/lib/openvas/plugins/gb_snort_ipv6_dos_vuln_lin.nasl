###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_snort_ipv6_dos_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Snort 'IPv6' Packet Denial Of Service Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation could allow attacker to crash an affected application,
  creating a denial of service condition.
  Impact Level: Application";
tag_affected = "Snort version prior to 2.8.5.1 on Linux.";
tag_insight = "This flaw is caused by an error when processing malformed IPv6 packets when
  the application is compiled with the '--enable-ipv6' option and is running
  in verbose mode (-v).";
tag_solution = "Upgrade to Snort version 2.8.5.1 or later
  For updates, Refer http://www.snort.org/downloads";
tag_summary = "This host has Snort installed and is prone to Denial of Service
  vulnerability.";

if(description)
{
  script_id(801139);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-02 14:39:30 +0100 (Mon, 02 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3641");
  script_bugtraq_id(36795);
  script_name("Snort 'IPv6' Packet Denial Of Service Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37135");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53912");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3014");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=530863");

  script_description(desc);
  script_summary("Check for the version of Snort");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_snort_detect_lin.nasl");
  script_require_keys("Snort/Linux/Ver");
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

snortVer  = get_kb_item("Snort/Linux/Ver");
if(!snortVer ){
  exit(0);
}

# Check for Snort version < 2.8.5.1
if(version_is_less(version:snortVer , test_version:"2.8.5.1")){
  security_warning(0);
}

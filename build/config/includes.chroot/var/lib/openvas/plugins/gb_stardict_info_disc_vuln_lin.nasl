###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_stardict_info_disc_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# StarDict Information Disclosure Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to gain sensitive information
  by sniffing the network.
  Impact Level: Application";
tag_affected = "StarDict version 3.0.1 on Linux";
tag_insight = "Error exists when 'enable net dict' is configured, and it attempts to grab
  clipboard and sends it over network.";
tag_solution = "No solution or patch is available as of 07th July, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://stardict.sourceforge.net";
tag_summary = "This host is installed with StarDict and is prone to Information
  Disclosure Vulnerability.";

if(description)
{
  script_id(800644);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2260");
  script_name("StarDict Information Disclosure Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/504583");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=508945");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=534731");

  script_description(desc);
  script_summary("Check for the version of StarDict");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_stardict_detect_lin.nasl");
  script_require_keys("StarDict/Linux/Ver");
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

stardictVer = get_kb_item("StarDict/Linux/Ver");
if(!stardictVer){
  exit(0);
}

if(stardictVer)
{
  # Check for StarDict version 3.0.1-4.1 (3.0.1)
  if(version_is_equal(version:stardictVer, test_version:"3.0.1")){
    security_warning(0);
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_irfanview_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# IrfanView Buffer Overflow Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_insight = "The flaws are due to,
   - A sign extension error when parsing certain 'PSD' images
   - A boundary error when processing certain 'RLE' compressed 'PSD' images.

   These can be exploited to cause a heap-based buffer overflow by tricking a
   user into opening a specially crafted PSD file.";

tag_impact = "Successful exploitation will allow attacker to allow execution of arbitrary
  code or to compromise a user's system.
  Impact Level: System/Application.";
tag_affected = "IrfanView version prior to 4.27";
tag_solution = "Upgrade to version 4.27 or later,
  For updates refer to http://www.irfanview.com";
tag_summary = "This host has IrfanView installed and is prone to buffer overflow
  vulnerabilities.";

if(description)
{
  script_id(801338);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-1510", "CVE-2010-1509");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("IrfanView Buffer Overflow Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39036");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-41");

  script_description(desc);
  script_summary("Check for the version of IrfanView");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_irfanview_detect.nasl");
  script_require_keys("IrfanView/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("version_func.inc");

irViewVer = get_kb_item("IrfanView/Ver");
if(!irViewVer){
  exit(0);
}

# Check for IrfanVies version < 4.27
if(version_is_less(version:irViewVer, test_version:"4.27")){
  security_warning(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_designworks_professional_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# DesignWorks Professional '.cct' File BOF Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let the remote attackers execute arbitrary code
  by tricking a user into opening a specially crafted file and can cause stack
  overflow in the context of the affected application.
  Impact Level: Application";
tag_affected = "DesignWorks Professional version 5.0.7 and prior.";
tag_insight = "Boundary error exists when processing '.cct' files.";
tag_solution = "No solution or patch is available as of 18th March, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.capilano.com/html/dwwp.html";
tag_summary = "The host is installed with DesignWorks Professional and is prone
  to stack overflow vulnerability.";

if(description)
{
  script_id(800368);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-18 05:31:55 +0100 (Wed, 18 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-6363");
  script_bugtraq_id(32667);
  script_name("DesignWorks Professional '.cct' File BOF Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33043");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7362");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2008/3369");

  script_description(desc);
  script_summary("Check for the version of DesignWorks Professional");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_designworks_professional_detect.nasl");
  script_require_keys("DesignWorks/Prof/Ver");
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

dwpVer = get_kb_item("DesignWorks/Prof/Ver");
if(!dwpVer){
  exit(0);
}

# Check for DesignWorks Professional version 5.0.7 or prior
if(version_is_less_equal(version:dwpVer, test_version:"5.0.7")){
  security_hole(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_slysoft_prdts_code_exec_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# SlySoft Product(s) Code Execution Vulnerability
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
tag_impact = "Successful exploitation will let the attacker cause memory corruption and
  can allow remote code execution in the context of the affected system,
  which result in service crash.
  Impact Level: System/Application";
tag_affected = "SlySoft AnyDVD version prior to 6.5.2.6
  SlySoft CloneCD version 5.3.1.3 and prior
  SlySoft CloneDVD version 2.9.2.0 and prior
  SlySoft Virtual CloneDrive version 5.4.2.3 and prior";
tag_insight = "METHOD_NEITHER communication method for IOCTLs does not properly validate
  a buffer associated with the Irp object of user space data provided to
  the ElbyCDIO.sys kernel driver.";
tag_solution = "Upgrade to higher versions accordingly
  http://www.slysoft.com/en/download.html";
tag_summary = "This host is installed with SlySoft Product(s) and are prone
  to Code Execution Vulnerability.";

if(description)
{
  script_id(800392);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-16 16:39:16 +0200 (Thu, 16 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-0824");
  script_bugtraq_id(34103);
  script_name("SlySoft Product(s) Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34269");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34289");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34287");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34288");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/501713/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of SlySoft Product(s)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_slysoft_prdts_detect.nasl");
  script_require_keys("AnyDVD/Ver", "CloneCD/Ver", "CloneDVD/Ver",
                      "VirtualCloneDrive/Ver");
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

# Grep the version for AnyDVD prior to 6.5.2.6
anydvdVer = get_kb_item("AnyDVD/Ver");
if(anydvdVer)
{
  if(version_is_less(version:anydvdVer, test_version:"6.5.2.6"))
  {
    security_warning(0);
    exit(0);
  }
}

# Grep the version for CloneCD 5.3.1.3 and prior
clonecdVer = get_kb_item("CloneCD/Ver");
if(clonecdVer)
{
  if(version_is_less_equal(version:clonecdVer, test_version:"5.3.1.3"))
  {
    security_warning(0);
    exit(0);
  }
}

# Grep the version for CloneDVD 2.9.2.0 and prior
clonedvdVer = get_kb_item("CloneDVD/Ver");
if(clonedvdVer)
{
  if(version_is_less_equal(version:clonedvdVer, test_version:"2.9.2.0"))
  {
    security_warning(0);
    exit(0);
  }
}

# Grep the version for Virtual CloneDrive 5.4.2.3 and prior
vcdVer = get_kb_item("VirtualCloneDrive/Ver");
if(vcdVer)
{
  if(version_is_less_equal(version:vcdVer, test_version:"5.4.2.3")){
    security_warning(0);
  }
}

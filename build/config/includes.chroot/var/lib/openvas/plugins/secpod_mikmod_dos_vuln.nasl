###############################################################################
# OpenVAS Vulnerability Test
# $Id:secpod_mikmod_dos_vuln.nasl 879 2009-01-22 15:10:29Z jan $
#
# MikMod Module Player Denial of Service Vulnerability (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the attacker crash the application to cause
  denial-of-service condition.

  Impact level: Application";

tag_affected = "MikMod Module Player version 3.1.11 to 3.2.0 on Linux.";
tag_insight = "- libmikmod library using a global variable to keep track of the number of
    channels can be exploited to crash an application using the library by
    loading a module with more channels than the currently playing module.
  - Error when processing the header of certain XM files which can be
    exploited to crash an application using the library via a specially
    crafted XM file.";
tag_solution = "Apply Patch,
  http://bugs.debian.org/cgi-bin/bugreport.cgi?msg=5;filename=31.xm-header.patch;att=1;bug=476339";
tag_summary = "This host is installed with MikMod Module Player and is prone to
  Denial of Service vulnerability.";

if(description)
{
  script_id(900443);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-29 15:16:47 +0100 (Thu, 29 Jan 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-0179");
  script_bugtraq_id(33235);
  script_name("MikMod Module Player Denial of Service Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33485");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=461519");

  script_description(desc);
  script_summary("Check for the version of MikMod Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_mikmod_detect.nasl");
  script_require_keys("MikMod/Linux/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

mikmodVer = get_kb_item("MikMod/Linux/Ver");
if(mikmodVer != NULL)
{
  #Grep for MikMod version 3.1.11 to 3.2.0
  if(version_in_range(version:mikmodVer, test_version:"3.1.11",
                                         test_version2:"3.2.0")){
    security_warning(0);
  }
}

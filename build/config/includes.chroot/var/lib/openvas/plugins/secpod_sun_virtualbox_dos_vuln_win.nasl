###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_virtualbox_dos_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Sun VirtualBox or xVM VirtualBox Denial Of Service Vulnerability (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will let attacker to exhaust the kernel memory of the
  guest operating system, leading to a Denial of Service against the guest
  operating system running in a virtual machine.
  Impact Level: Application.";
tag_affected = "Sun VirtualBox version 3.x before 3.0.10
  Sun xVM VirtualBox 1.6.x and 2.0.x before 2.0.12, 2.1.x, and 2.2.x";
tag_insight = "The flaw is due to the unspecified vulnerability in Guest Additions,
  via unknown vectors.";
tag_solution = "Upgrade to Sun VirtualBox version 3.0.10 or Sun xVM VirtualBox 2.0.12
  http://www.virtualbox.org/wiki/Downloads";
tag_summary = "This host is installed with Sun VirtualBox or xVM VirtualBox and is
  prone to Denial Of Service vulnerability.";

if(description)
{
  script_id(901054);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3940");
  script_bugtraq_id(37024);
  script_name("Sun VirtualBox or xVM VirtualBox Denial Of Service Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37363/");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/387766.php");
  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-66-271149-1");

  script_description(desc);
  script_summary("Check for the version of Sun VirtualBox or Sun xVM VirtualBox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_require_keys("Sun/VirtualBox/Win/Ver", "Sun/xVM-VirtualBox/Win/Ver");
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

# Check for product Sun VirtuaBox
vmVer = get_kb_item("Sun/VirtualBox/Win/Ver");
if(vmVer != NULL)
{
  if(version_in_range(version:vmVer, test_version:"2.0.0", test_version2:"2.0.11")||
     version_in_range(version:vmVer, test_version:"2.2.0", test_version2:"2.2.4")||
     version_in_range(version:vmVer, test_version:"3.0.0", test_version2:"3.0.9"))
  {
    security_warning(0);
    exit(0);
  }
}

# Check for product Sun xVM VirtuaBox
xvmVer = get_kb_item("Sun/xVM-VirtualBox/Win/Ver");
if(xvmVer != NULL)
{
  if(version_in_range(version:xvmVer, test_version:"1.6.0", test_version2:"1.6.6") ||
     version_in_range(version:xvmVer, test_version:"2.0.0", test_version2:"2.0.11") ||
     version_in_range(version:xvmVer, test_version:"2.1.0", test_version2:"2.1.4") ||
     version_in_range(version:xvmVer, test_version:"2.2.0", test_version2:"2.2.4")){
    security_warning(0);
  }
}

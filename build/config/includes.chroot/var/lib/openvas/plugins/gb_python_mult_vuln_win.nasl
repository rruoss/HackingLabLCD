##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_python_mult_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Python Multiple Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
##############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation could allows attackers to access sensitive information
  or cause a denial of service of a Python web application, processing URLs, via
  a specially-crafted urllib open URL request.";
tag_affected = "Python version 2.x before 2.7.2 and 3.x before 3.2.1";

tag_solution = "Apply the patch from below link,
  http://hg.python.org/cpython/file/5937d2119a20/Lib/test/test_urllib2.py

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_insight = "The flaws are due to error in handling 'ftp://' and 'file://' URL
  schemes in the Python urllib and urllib2 extensible libraries processed the
  urllib open URL request.";
tag_summary = "This host is installed with Python and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801797);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_cve_id("CVE-2011-1521");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"risk_factor", value:"High");
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

  script_xref(name : "URL" , value : "http://bugs.python.org/issue11662");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=690560");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2011/03/24/5");

  script_description(desc);
  script_summary("Check for vulnerable version of Python");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_name("Python Multiple Vulnerabilities (Windows)");
  script_dependencies("gb_python_detect_win.nasl");
  script_require_keys("SMB/WindowsVersion","Python/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("version_func.inc");

## Get the version from KB
pyVer = get_kb_item("Python/Win/Ver");
if(!pyVer){
  exit(0);
}

## Check for Python Version
if(version_in_range(version:pyVer, test_version:"2.0", test_version2:"2.7.1") ||
   version_in_range(version:pyVer, test_version:"3.0", test_version2:"3.2.0")){
  security_hole(0);
}

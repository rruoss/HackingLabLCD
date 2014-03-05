###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_dos_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Perl Denial of Service Vulnerability (Windows)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to cause an affected
  application to crash, denying service to legitimate users.
  Impact Level: Application";
tag_affected = "Perl versions 5.10 and 5.10.1 on Windows.";
tag_insight = "The flaw is due to an error in 'getpeername', 'readdir', 'closedir',
  'getsockname', 'rewinddir', 'tell', or 'telldir' function calls. When given
  a wrong number of arguments, those functions will attempt to perform a
  comparison between an unallocated memory zone and a given register, resulting
  in a segmentation fault.";
tag_solution = "Upgrade to Perl version 5.12 or later.
  For updates refer to http://www.perl.org/get.html";
tag_summary = "The host is installed with Perl and is prone to denial of service
  vulnerability.";

if(description)
{
  script_id(801790);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)");
  script_cve_id("CVE-2011-0761");
  script_bugtraq_id(47766);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Perl Denial of Service Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/67355");
  script_xref(name : "URL" , value : "http://www.toucan-system.com/advisories/tssa-2011-03.txt");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/517916/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Perl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_perl_detect_win.nasl");
  script_require_keys("Strawberry/Perl/Ver", "ActivePerl/Ver");
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

apVer = get_kb_item("ActivePerl/Ver");
if(apVer)
{
  if(version_in_range(version:apVer, test_version:"5.10", test_version2:"5.10.1"))
  {
    security_warning(0);
    exit(0);
  }
}

spVer = get_kb_item("Strawberry/Perl/Ver");
if(spVer)
{
  if(version_in_range(version:spVer, test_version:"5.10", test_version2:"5.10.1")){
    security_warning(0);
  }
}

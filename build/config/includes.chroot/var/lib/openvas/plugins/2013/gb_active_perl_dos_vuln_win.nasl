###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_active_perl_dos_vuln_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Active Perl Denial of Service Vulnerability (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to cause denial of service
  (memory consumption) via specially-crafted hash key.
  Impact Level: Application";

tag_affected = "Active Perl versions 5.8.2 before 5.14.4 and 5.15 before 5.16.3 on Windows";
tag_insight = "Flaw is due to an error when rehashing user-supplied input.";
tag_solution = "Upgrade to Active Perl version 5.16.3 or 5.14.4 or later,
  For updates refer to http://www.perl.org/get.html";
tag_summary = "The host is installed with Active Perl and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(803370);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1667");
  script_bugtraq_id(58311);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-09 16:40:23 +0530 (Tue, 09 Apr 2013)");
  script_name("Active Perl Denial of Service Vulnerability (Windows)");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://osvdb.org/90892");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52472");
  script_xref(name : "URL" , value : "http://perlnews.org/2013/03/rehashing-flaw");
  script_xref(name : "URL" , value : "http://perlnews.org/2013/03/perl-5-16-3-and-5-14-4-just-released");
  script_xref(name : "URL" , value : "http://www.nntp.perl.org/group/perl.perl5.porters/2013/03/msg199755.html");
  script_summary("Check for the vulnerable version of Active Perl on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("ActivePerl/Ver");
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

## Variable Initialization
apVer = "";

## Get version from KB
apVer = get_kb_item("ActivePerl/Ver");
if(apVer && apVer =~ "^5\.")
{
  if(version_in_range(version:apVer, test_version:"5.8.2", test_version2:"5.14.3")||
     version_in_range(version:apVer, test_version:"5.15", test_version2:"5.16.2"))
  {
    security_hole(0);
    exit(0);
  }
}

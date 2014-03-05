###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_activeperl_modules_mult_vuln_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Active Perl Modules Multiple Vulnerabilities (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Upgrade to Perl 5.14.2 or latr,
  Upgrade to Active Perl PAR module version 1.003 or later
  Upgrade to Active Perl Digest module version 1.17 or later
  Upgrade to Active Perl Encode module version 2.44 or later
  Upgrade Active Perl PAR::Packer module version 1.012 or later
  For updates refer to http://www.perl.org/get.html

  *****
  NOTE: Ignore this warning if above mentioned versions of modules are already installed.
  *****";

tag_impact = "Successful exploitation will allow attackers to cause an affected
  application to crash or execute arbitrary perl code.
  Impact Level: System/Application";

tag_affected = "Active Perl PAR module before 1.003
  Active Perl Digest module before 1.17
  Active Perl Encode module before 2.44
  Active Perl PAR::Packer module before 1.012 on winows";
tag_insight = "The flaws are due to
  - an error in par_mktmpdir function in the 'PAR::Packer' and 'PAR' modules
    creates temporary files in a directory with a predictable name without
    verifying ownership and permissions of this directory.
  - the 'Digest->new()' function not properly sanitising input before using it
    in an 'eval()' call, which can be exploited to inject and execute arbitrary
    perl code.
  - off-by-one error in the decode_xs function in Unicode/Unicode.xs in the
    'Encode' module.
  - An error within the 'File::Glob::bsd_glob()' function when handling the
    GLOB_ALTDIRFUNC flag can be exploited to cause an access violation and
    potentially execute arbitrary code.";
tag_summary = "The host is installed with Active Perl and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803343);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2011-5060", "CVE-2011-4114", "CVE-2011-3597", "CVE-2011-2939",
                "CVE-2011-2728");
  script_bugtraq_id(49911);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-27 11:15:50 +0530 (Wed, 27 Mar 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Active Perl Modules Multiple Vulnerabilities (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46172");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46279");
  script_xref(name : "URL" , value : "http://search.cpan.org/dist/Digest/Digest.pm");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=731246");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=753955");
  script_xref(name : "URL" , value : "https://rt.cpan.org/Public/Bug/Display.html?id=69560");
  script_summary("Check for the vulnerable version of Active Perl on windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("ActivePerl/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

## Perl Digest and Perl Encode modules are the default modules in perl
## Checking for the perl versions < 5.14.2, because all perl versions are
## having Digest and Encode modules < 1.17 and 2.44 respectively

apVer = get_kb_item("ActivePerl/Ver");
if(apVer)
{
  if(version_is_less(version:apVer, test_version:"5.14.2"))
  {
    security_hole(0);
    exit(0);
  }
}

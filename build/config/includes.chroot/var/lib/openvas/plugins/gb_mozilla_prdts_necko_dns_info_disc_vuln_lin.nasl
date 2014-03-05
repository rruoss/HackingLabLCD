###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_necko_dns_info_disc_vuln_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mozilla Products Necko DNS Information Disclosure Vulnerability (Linux)
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
tag_solution = "Apply the patch or Upgrade to  Mozilla Necko version 1.9.1
  http://www.mozilla.com/en-US/products/
  https://bug492196.bugzilla.mozilla.org/attachment.cgi?id=377824

  *****
  NOTE: Ignore this warning, if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation will let the attackers obtain the network location of
  the applications user by logging DNS requests.
  Impact Level: Application";
tag_affected = "Mozilla Thunderbird version 3.0.1 and
  Seamonkey with Mozilla Necko version 1.9.0 and prior on Linux.";
tag_insight = "The flaw exists while DNS prefetching, when the app type is 'APP_TYPE_MAIL'
  or 'APP_TYPE_EDITOR'";
tag_summary = "The host is installed with Thundebird/Seamonkey and is prone to
  Information Disclosure vulnerability.";

if(description)
{
  script_id(800456);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-4629");
  script_name("Mozilla Products Necko DNS Information Disclosure Vulnerability (Linux)");
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

  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=492196");
  script_xref(name : "URL" , value : "https://secure.grepular.com/DNS_Prefetch_Exposure_on_Thunderbird_and_Webmail");

  script_description(desc);
  script_summary("Check for the version of Thunderbird/Seamonkey");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_lin.nasl", "gb_thunderbird_detect_lin.nasl");
  script_require_keys("Seamonkey/Linux/Ver", "Thunderbird/Linux/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

# Thunderbird Check
fpVer = get_kb_item("Thunderbird/Linux/Ver");
if(!isnull(fpVer))
{
  if(version_is_less_equal(version:fpVer, test_version:"3.0.1"))
  {
    security_warning(0);
    exit(0);
  }
}

# Seamonkey Check
seaVer = get_kb_item("Seamonkey/Linux/Ver");
if(!seaVer){
  exit(0);
}

grep = find_bin(prog_name:"grep", sock:sock);
grep = chomp(grep[0]);
garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("rv:[0-9.].\\+");

modName = find_file(file_name:"libnecko.so", file_path:"/",
                    useregex:TRUE, regexpar:"$", sock:sock);

foreach binaryName (modName)
{
  binaryName = chomp(binaryName);
  arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) +
        garg[3] + raw_string(0x22) + " " + binaryName;

  seaVer = get_bin_version(full_prog_name:grep, version_argv:arg,
                           ver_pattern:"([0-9.]+)", sock:sock);
  if(seaVer[1] != NULL)
  {
    if(version_is_less(version:seaver[1], test_version:"1.9.1"))
    {
      security_warning(0);
      ssh_close_connection();
      exit(0);
    }
  }
}

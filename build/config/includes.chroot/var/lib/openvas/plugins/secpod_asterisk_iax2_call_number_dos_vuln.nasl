###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_asterisk_iax2_call_number_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Asterisk IAX2 Call Number Exhaustion DOS Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_solution = "Upgrade to version 1.2.35, 1.4.26.2, 1.6.0.15, 1.6.1.6 or apply the patch
  http://www.asterisk.org/downloads
  http://downloads.asterisk.org/pub/security/AST-2009-006-1.2.diff.txt
  http://downloads.asterisk.org/pub/security/AST-2009-006-1.4.diff.txt
  http://downloads.asterisk.org/pub/security/AST-2009-006-1.6.0.diff.txt
  http://downloads.asterisk.org/pub/security/AST-2009-006-1.6.1.diff.txt

  *****
  NOTE: Please ignore the warning if the patch is applied.
  *****";

tag_impact = "Successful exploitation will let the attacker cause to Denial of Service.
  Impact Level: Application";
tag_affected = "Asterisk version 1.2.x before 1.2.35, 1.4.x before 1.4.26.2,
  1.6.0.x before 1.6.0.15, and 1.6.1.x before 1.6.1.6 on Linux.";
tag_insight = "An error in the 'IAX2' protocol implementation while processing call-number
  which can be exploited by initiating many IAX2 message exchanges.";
tag_summary = "This host has Asterisk installed and is prone to Denial of Service
  vulnerability.";

if(description)
{
  script_id(900851);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2346");
  script_bugtraq_id(36275);
  script_name("Asterisk IAX2 Call Number Exhaustion DOS Vulnerability (Linux)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/36593/");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Sep/1022819.html");
  script_xref(name : "URL" , value : "http://downloads.asterisk.org/pub/security/AST-2009-006.html");

  script_description(desc);
  script_summary("Check for the version of Asterisk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_require_keys("Asterisk-PBX/Ver", "Asterisk-PBX/Installed");
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

function asteris_is_vulnerable(ver)
{
  # Check for Asterisk version 1.2 < 1.2.35, 1.4 < 1.4.26.2, 1.6.0 < 1.6.0.15 and
  #                            1.6.1 < 1.6.1.6
  if(version_in_range(version:ver, test_version:"1.2", test_version2:"1.2.34")||
     version_in_range(version:ver, test_version:"1.4", test_version2:"1.4.26.1")||
     version_in_range(version:ver, test_version:"1.6.0", test_version2:"1.6.0.14")||
     version_in_range(version:ver, test_version:"1.6.1", test_version2:"1.6.1.5")){
     return TRUE;
  }
}


msg = "Asterisk is Running on 5060/udp and Installed version is Vulnerable";
asteriskVer = get_kb_item("Asterisk-PBX/Ver");

if(asteriskVer)
{
  if(asteris_is_vulnerable(ver:asteriskVer))
  {
    security_hole(port:5060, proto:"udp");
  }
}
else if(get_kb_item("Asterisk-PBX/Installed"))
{
  astk_sock = ssh_login_or_reuse_connection();
  if(!astk_sock) {
    exit(0);
  }

  paths = find_file(file_name:"asterisk", file_path:"/", useregex:TRUE,
                    regexpar:"$", sock:astk_sock);

  foreach binName (paths)
  {
    asteriskVer = get_bin_version(full_prog_name:chomp(binName), sock:astk_sock,
                                  version_argv:"-V",
                                  ver_pattern:"Asterisk ([0-9.]+(.?[a-z0-9]+)?)");
    asteriskVer[1] = ereg_replace(pattern:"-", replace:".", string:asteriskVer[1]);
    if(asteriskVer[1] != NULL)
    {
      if(asteris_is_vulnerable(ver:asteriskVer[1]))
      {
        security_hole(port:5060, proto:"udp");
        ssh_close_connection();
        exit(0);
      }
    }
  }
  ssh_close_connection();
}

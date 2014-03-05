###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_greenbone_gsa_csrf_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Greenbone Security Assistant Cross-Site Request Forgery Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
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
tag_impact = "Successful exploitation will allow attacker to conduct cross-site request
  forgery attacks.";
tag_affected = "Greenbone Security Assistant version 1.0.3 and prior.";
tag_insight = "The application allows users to perform certain actions via HTTP requests
  without performing any validity checks to verify the requests. This can be
  exploited to execute arbitrary commands in OpenVAS Manager by tricking a
  logged in administrative user into visiting a malicious web site.";
tag_solution = "No solution or patch is available as of 12th April, 2011. Information
  regarding this issue will be updated soon once the details are available.
  For updates refer to http://www.openvas.org/";
tag_summary = "This host is installed with Greenbone Security Assistant and is
  prone to cross-site request forgery vulnerability.";

if(description)
{
  script_id(801919);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-13 15:50:09 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2011-0650");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Greenbone Security Assistant Cross-Site Request Forgery Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43092");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65012");
  script_xref(name : "URL" , value : "http://www.openvas.org/OVSA20110118.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/515971/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Greenbone Security Assistant");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Confirm Linux, as SSH can be instslled on Windows as well
result = ssh_cmd(socket:sock, cmd:"uname");
if("Linux" >!< result){
  exit(0);
}

## Check for the possible paaths
paths = find_bin(prog_name:"gsad", sock:sock);
foreach stardictbin (paths)
{
  ## Get the version by executing the command gsad
  gsadVer = get_bin_version(full_prog_name:chomp(stardictbin),
            sock:sock, version_argv:"--version",
            ver_pattern:"Greenbone Security Assistant ([0-9.]+)");

  if(gsadVer[1] != NULL)
  {
    # Grep for version 1.0.3 or prior
    if(version_is_less_equal(version:gsadVer[1], test_version:"1.0.3")){
      security_hole(0);
    }
    ssh_close_connection();
    exit(0);
  }
}
ssh_close_connection();

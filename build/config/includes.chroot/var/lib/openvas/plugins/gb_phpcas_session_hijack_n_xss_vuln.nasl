###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpcas_session_hijack_n_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# phpCAS Session Hijacking and Cross-Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected
  site and to hijack another user's account and gain the victims privileges.
  Impact Level: Application.";
tag_affected = "phpCAS version prior to 1.1.2";

tag_insight = "The flaw exists due to:
  - improper validation of service tickets prior to assigning the new session.
    This can be exploited to hijack another user's session by guessing valid
    service tickets.
  - improper validation of the callback URL.";
tag_solution = "Upgrade to phpCAS version 1.1.2 or later,
  For updates refer to https://wiki.jasig.org/display/CASC/phpCAS";
tag_summary = "This host is installed with phpCAS and is prone to session
  hijacking and cross-site scripting vulnerabilities.";

if(description)
{
  script_id(801428);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2010-2795", "CVE-2010-2796");
  script_bugtraq_id(42162,42160);
  script_name("phpCAS Session Hijacking and Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40845");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60894");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60895");
  script_xref(name : "URL" , value : "https://issues.jasig.org/browse/PHPCAS-61");

  script_description(desc);
  script_summary("Check for the version of phpCAS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Confirm Linux, as SSH can be instslled on Windows as well
result = ssh_cmd(socket:sock, cmd:"uname");
if("Linux" >!< result){
  exit(0);
}

paths = find_file(file_name:"CAS.php",file_path:"/usr/share/pear/",
                  useregex:TRUE, regexpar:"$", sock:sock);

foreach binName (paths)
{
  ## Grep the version
  casVer = get_bin_version(full_prog_name:"cat", version_argv:binName,
                           ver_pattern:"PHPCAS_VERSION'.? '([0-9.]+)",
                           sock:sock);

  if(casVer[1] != NULL)
  {
    ## Check phpCAS version < 1.1.2
    if(version_is_less(version:casVer[1], test_version:"1.1.2"))
    {
      security_warning(0);
      exit(0);
    }
  }
}
ssh_close_connection();

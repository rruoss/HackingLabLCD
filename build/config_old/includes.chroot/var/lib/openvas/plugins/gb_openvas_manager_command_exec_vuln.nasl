###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openvas_manager_command_exec_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# OpenVAS Manager OMP Request Handling Command Injection Vulnerability
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
tag_solution = "Apply the patch or upgrade to OpenVAS Manager 1.0.4, 2.0.2 or later,
  For update refer,
  http://www.openvas.org/
  http://www.openvas.org/OVSA20110118.html

  *****
  NOTE : Ignore this warning, if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation will allow attacker to execute arbitrary commands
  with the privileges of the OpenVAS Manager (typically root).";
tag_affected = "OpenVAS Manager versions prior to 1.0.4 and prior to 2.0.2";
tag_insight = "The flaw is due to an input validation error in the 'email()' function
  in 'manage_sql.c' while processing OMP (OpenVAS Management Protocol) requests
  sent by authenticated users of the GSA (Greenbone Security Assistant) web
  application.";
tag_summary = "This host is installed with OpenVAS Manager and is prone command
  injection vulnerability.";

if(description)
{
  script_id(801920);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-0018");
  script_bugtraq_id(45987);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("OpenVAS Manager OMP Request Handling Command Injection Vulnerability");
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

  script_xref(name : "URL" , value : "http://osvdb.org/70639");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43037");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65011");
  script_xref(name : "URL" , value : "http://www.openvas.org/OVSA20110118.html");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16086/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0208");

  script_description(desc);
  script_summary("Check for the version of OpenVAS Manager");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
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

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Confirm Linux, as SSH can be installed on Windows as well
result = ssh_cmd(socket:sock, cmd:"uname");
if("Linux" >!< result){
  exit(0);
}

## Check for the possible paths
paths = find_bin(prog_name:"openvasmd", sock:sock);
foreach stardictbin (paths)
{
  ## Get the version by executing the command gsad
  omVer = get_bin_version(full_prog_name:chomp(stardictbin),
                          sock:sock, version_argv:"--version",
                          ver_pattern:"OpenVAS Manager.*");

  if(omVer[0] != NULL)
  {
    omVer = eregmatch(pattern:"OpenVAS Manager ([0-9]\.[0-9]\.[0-9]+).?(rc[0-9]+)?",
                      string:omVer[0]);
    if(omVer[1] != NULL && omVer[2] != NULL)
    {
      ver = omVer[1] + "." + omVer[2];
    }
    else if(omVer [1]!= NULL  && omVer[2] == NULL){
      ver =omVer[1];
    }
  }

  if(ver)
  {
    ## Grep for version 1.0.3 or prior
    if(version_in_range(version:ver, test_version:"1.0", test_version2:"1.0.3") ||
       version_in_range(version:ver, test_version:"2.0", test_version2:"2.0.1"))
    {
      security_hole(0);
      exit(0);
    }
  }
}
ssh_close_connection();

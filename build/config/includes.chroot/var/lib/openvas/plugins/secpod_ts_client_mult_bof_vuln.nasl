###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ts_client_mult_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Terminal Server Client RDP File Processing BOF Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation allows attackers to execute arbitrary code,
  crash the application or deny service to legitimate users.
  Impact Level: Application.";
tag_affected = "Terminal Server Client version 0.150";

tag_insight = "Multiple flaws are due to a boundary error in the 
  'tsc_launch_remote()' function, when processing a 'hostname', 'username',
  'password' and 'domain' parameters.";
tag_solution = "No solution or patch is available as of 25th February, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/tsclient/";
tag_summary = "This host is installed with Terminal Server Client and is prone to
  multiple buffer overflow vulnerabilities.";

if(description)
{
  script_id(902297);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_cve_id("CVE-2011-0900", "CVE-2011-0901");
  script_bugtraq_id(46099);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Terminal Server Client RDP File Processing BOF Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/70749");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43120");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65100");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16095/");

  script_description(desc);
  script_summary("Check for the version of Terminal Server Client");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Buffer overflow");
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

## Check the file path
paths = find_file(file_name:"NEWS.gz",file_path:"/doc/tsclient/",
                  useregex:TRUE, regexpar:"$", sock:sock);
## check for each path
foreach binName (paths)
{
  ## get the version by reading file using zcat command
  tscVer = get_bin_version(full_prog_name:"zcat", version_argv:binName,
                ver_pattern:"v.([0-9]\.[0-9]+)" ,sock:sock);
  
  ##  check version
  if(tscVer[1] != NULL)
  {
    ## Check tsclient version equal to 0.150
    if(version_is_equal(version:tscVer[1], test_version:"0.150"))
    {
      security_hole(0);
      exit(0);
    }
  }
}

## Close the socket
ssh_close_connection();

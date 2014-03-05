###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sshd_challenge_resp_authentication_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# OpenSSH 'sshd' Challenge Response Authentication Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allows remote attackers to execute arbitrary
  code and gain escalated privileges.
  Impact Level: Application";
tag_affected = "OpenSSH versions 2.3.1 to 3.3";
tag_insight = "The flaw is due to an error in handling a large number of responses
  during challenge response authentication when using PAM modules with
  interactive keyboard authentication (PAMAuthenticationViaKbdInt).";
tag_solution = "Upgrade to OpenSSH version 3.4 or later
  For updates refer to http://www.openssh.com/";
tag_summary = "The host is running OpenSSH sshd with ChallengeResponseAuthentication
  enabled and is prone to buffer overflow vulnerability.";

if(description)
{
  script_id(802407);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2002-0640");
  script_bugtraq_id(5093);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-07 18:20:44 +0530 (Wed, 07 Dec 2011)");
  script_name("OpenSSH 'sshd' Challenge Response Authentication Buffer Overflow Vulnerability");
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
  script_summary("Check if ChallengeResponseAuthentication is enabled in OpenSSH");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://osvdb.org/839");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/369347");
  script_xref(name : "URL" , value : "http://www.cert.org/advisories/CA-2002-18.html");
  script_xref(name : "URL" , value : "http://marc.info/?l=bugtraq&amp;m=102521542826833&amp;w=2");
  exit(0);
}

include("backport.inc");
include("version_func.inc");

## Get the default port
port = get_kb_item("Services/ssh");
if(!port){
  port = 22;
}

## Get th SSH banner
banner = get_kb_item("SSH/banner/" + port );
if(!banner){
  exit(0);
}

banner = tolower(get_backport_banner(banner:banner));
ver = eregmatch(pattern:"ssh-.*openssh[_-]{1}([0-9.]+[p0-9]*)", string:banner);
## Get version from the banner
if(isnull(ver[1])){
 exit(0);
}

## Check the versions prior to 2.x and 3.x
if(ver[1] =~ "^(2|3)\..*")
{
  ## Check the versions prior to 3.4
  if(version_is_less(version:ver[1], test_version:"3.4"))
  {
    ## Get the supported protocols versions from kb
    auth = get_kb_item("SSH/supportedauth/" + port);
    if(auth)
    {
      ## Check the authentication method is challenge response
      ## authentication using PAM modules with interactive keyboard
      ## authentication
      if("keyboard-interactive" >< auth){
        security_hole(port);
      }
    }
  }
}

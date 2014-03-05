###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sshd_gssapi_credential_disclosure_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# OpenSSH 'sshd' GSSAPI Credential Disclosure Vulnerability
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
tag_impact = "Successful exploitation could allows remote attackers to bypass security
  restrictions and gain escalated privileges.
  Impact Level: Application";
tag_affected = "OpenSSH version prior to 4.2";
tag_insight = "The flaw is due to an error in handling GSSAPI credential delegation,
  Which allow GSSAPI credentials to be delegated to users who log in with
  methods other than GSSAPI authentication (e.g. public key) when the client
  requests it.";
tag_solution = "Upgrade OpenSSH to 4.2 or later,
  For updates refer to http://www.openssh.com/";
tag_summary = "The host is running OpenSSH sshd with GSSAPI enabled and is prone
  to credential disclosure vulnerability.";

if(description)
{
  script_id(902488);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2005-2798");
  script_bugtraq_id(14729);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-16 12:24:22 +0530 (Wed, 16 Nov 2011)");
  script_name("OpenSSH 'sshd' GSSAPI Credential Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/19141");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/16686");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1014845");
  script_xref(name : "URL" , value : "https://lists.mindrot.org/pipermail/openssh-unix-announce/2005-September/000083.html");

  script_description(desc);
  script_summary("Check for the credential disclosure vulnerability OpenSSH");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod ");
  script_family("General");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
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

## Check the versions prior to 4.2
if(version_is_less(version:ver[1], test_version:"4.2"))
{
  ## Get the supported protocols versions from kb
  auth = get_kb_item("SSH/supportedauth/" + port);
  if(auth)
  {
    ## Check the authentication method and confirm the vulnerability
    if("gssapi" >< auth){
      security_warning(port);
    }
  }
}

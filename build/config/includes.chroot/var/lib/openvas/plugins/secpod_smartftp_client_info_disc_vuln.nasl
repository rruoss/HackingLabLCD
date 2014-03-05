###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_smartftp_client_info_disc_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# SmartFTP Client Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the local attacker gain sensitive
  information about the victim's mail folders and can view their contents.
  Impact Level: Application.";
tag_affected = "SmartFTP Client version 4.0.1194.0 and prior.";

tag_insight = "The flaw exists due to the SmartFTP client is not properly saving the
  passwords, which allows attackers to find saved login credentials.";
tag_solution = "No solution or patch is available as of 23rd June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.smartftp.com/download/";
tag_summary = "This host is installed with SmartFTP Client and is prone to
  information disclosure vulnerability.";

if(description)
{
  script_id(902448);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("SmartFTP Client Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/102432/smartftp-disclose.rb.txt");
  script_xref(name : "URL" , value : "http://cosine-security.blogspot.com/2011/06/windows-cryptography-with-metasploit.html");

  script_description(desc);
  script_summary("Check for the version of SmartFTP Client");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("FTP");
  script_dependencies("secpod_smartftp_client_detect.nasl");
  script_require_keys("SmartFTP/Client/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);

}


include("version_func.inc");

sftpVer = get_kb_item("SmartFTP/Client/Ver");
if(sftpVer != NULL)
{
   # Check for SmartFTP <= 4.0.1194.0
   if(version_is_less_equal(version:sftpVer, test_version:"4.0.1194.0")){
   security_warning(0);
  }
}

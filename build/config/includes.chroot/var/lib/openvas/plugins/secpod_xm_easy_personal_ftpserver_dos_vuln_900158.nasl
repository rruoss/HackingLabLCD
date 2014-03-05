##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xm_easy_personal_ftpserver_dos_vuln_900158.nasl 16 2013-10-27 13:09:52Z jan $
# Description: XM Easy Personal FTP Server 'NSLT' Command Remote DoS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

include("revisions-lib.inc");
tag_summary = "The host is running XM Easy Personal FTP Server, which is prone to
  denial of service vulnerability.

  The vulnerability is due to an error when handling a malformed NLST command.";

tag_impact = "Successful exploitation will cause denial of service to legitimate users.
  Impact Level: Application";
tag_affected = "dxmsoft XM Easy Personal FTP Server version 5.6.0 and prior on Windows (all)";
tag_solution = "No solution or patch is available as of 17th October, 2008.";

if(description)
{
  script_id(900158);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-21 15:08:20 +0200 (Tue, 21 Oct 2008)");
  script_cve_id("CVE-2008-5626");
 script_bugtraq_id(31739);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("XM Easy Personal FTP Server 'NSLT' Command Remote DoS Vulnerability");
  script_summary("Check for vulnerable version of XM Easy Personal FTP Server");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  script_xref(name : "URL" , value : "http://www.dxm2008.com/");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6741");

  script_description(desc);
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
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

if(!get_port_state(port)){
  exit(0);
}

banner = get_ftp_banner(port:port);
if("DXM's FTP Server" >!< banner){
  exit(0);
}

if(egrep(pattern:"DXM's FTP Server 5\.([0-5](\..*)?|6\.0)($|[^.0-9])",
         string:banner))
{
  security_warning(port);
  exit(0);
}

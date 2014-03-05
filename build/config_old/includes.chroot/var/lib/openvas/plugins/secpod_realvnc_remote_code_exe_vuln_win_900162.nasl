##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_realvnc_remote_code_exe_vuln_win_900162.nasl 16 2013-10-27 13:09:52Z jan $
# Description: RealVNC VNC Viewer Remote Code Execution Vulnerability (Win)
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
tag_summary = "This host has RealVNC VNC Viewer installed and is prone to security
  vulnerability.

  The flaw is due to error in 'CMsgReader::readRect()' function in
  common/rfb/CMsgReader.cxx processing encoding types, and is exploited by
  sending specially crafted messages to the application.";

tag_impact = "Successful exploitation will allow execution of arbitrary code when user
  connects to a malicious server.
  Impact Level: Application";
tag_affected = "RealVNC VNC Free Edition version prior to 4.1.3";
tag_solution = "Update to version 4.1.3
  http://www.realvnc.com/products/download.html";

if(description)
{
  script_id(900162);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-29 14:53:11 +0100 (Wed, 29 Oct 2008)");
  script_cve_id("CVE-2008-4770");
 script_bugtraq_id(31832);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("RealVNC VNC Viewer Remote Code Execution Vulnerability (Win)");
  script_summary("Check for vulnerable version of RealVNC");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


  script_description(desc);
  script_dependencies("secpod_reg_enum.nasl", "find_service.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports("Services/vnc", 5800, 139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32317/");
  script_xref(name : "URL" , value : "http://www.realvnc.com/products/free/4.1/release-notes.html");
  exit(0);
}


include("smb_nt.inc");
include("http_func.inc");

port = get_kb_item("Services/vnc");
if(!port){
  port = 5800;
}

if(!get_port_state(port)){
  exit(0);
}

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if("RealVNC/4.0" >!< get_http_banner(port)){
  exit(0);
}

vncVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                             "\Uninstall\RealVNC_is1",
                         item:"DisplayVersion");

if(egrep(pattern:"^(4\.[01](\.[0-2])?)($|[^.0-9])", string:vncVer)){
  security_hole(port);
}

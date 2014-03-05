###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_edir_mult_vuln_nov08_win.nasl 16 2013-10-27 13:09:52Z jan $
#
# Novell eDirectory Multiple Vulnerabilities Nov08 - (Win)
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
tag_impact = "Successful exploitation allows remote code execution on the target
  machines or can allow disclosure of potentially sensitive information
  or can cause denial of service.
  Impact Level: Application";
tag_affected = "Novell eDirectory 8.8 SP2 and prior on Windows.";
tag_insight = "The flaws are due to
  - boundary error in LDAP and NDS services.
  - boundary error in HTTP language header and HTTP content-length header.
  - HTTP protocol stack(HTTPSTK) that does not properly filter HTML code from
    user-supplied input.";
tag_solution = "Update to 8.8 Service Pack 3.
  http://support.novell.com/patches.html";
tag_summary = "This host is running Novell eDirectory and is prone to Multiple
  Vulnerabilities.";

if(description)
{
  script_id(800135);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-5091", "CVE-2008-5092", "CVE-2008-5093", "CVE-2008-5094");
  script_bugtraq_id(30947);
  script_name("Novell eDirectory Multiple Vulnerabilities Nov08 - (Win)");
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
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Aug/1020785.html");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Aug/1020786.html");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Aug/1020787.html");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Aug/1020788.html");
  script_xref(name : "URL" , value : "http://www.novell.com/support/viewContent.do?externalId=3426981");
  script_xref(name : "URL" , value : "http://www.novell.com/documentation/edir873/sp10_readme/netware/readme.txt");

  script_description(desc);
  script_summary("Check for the Version of Novell eDirectory");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

port = 8028;
if(!get_port_state(port))
{
  port = 8030;
  if(!get_port_state(port)){
    exit(0);
  }
}

eDirVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\Uninstall\NDSonNT", item:"DisplayName");
eDirVer = eregmatch(pattern:"Novell eDirectory ([0-9.]+ (SP[0-9]+)?)",
                    string:eDirVer);
if(eDirVer != NULL)
{
  eDirVer = ereg_replace(pattern:" ", string: eDirVer[1], replace:".");
  if(version_is_less(version:eDirVer, test_version:"8.8.SP3")){
    security_hole(port);
  }
}

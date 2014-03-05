##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hummingbird_activex_bof_vuln_900159.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Hummingbird HostExplorer ActiveX Control BOF Vulnerability
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
tag_summary = "This host has Hummingbird HostExplorer ActiveX Control installed
  and is prone to stack based buffer overflow vulnerability.

  The flaw is due to error in Hummingbird.XWebHostCtrl.1 ActiveX control in
  hclxweb.dll file when handling the 'PlainTextPassword' function, which can
  be exploited by assigning an overly long string.";

tag_impact = "Successful exploitation will allow execution arbitrary code, and deny the
  service.
  Impact Level: Application ";
tag_affected = "Hummingbird HostExplorer versions prior to 2008 on Windows (all)";
tag_solution = "Update to HostExplorer 2008
  http://connectivity.hummingbird.com/products/nc/he/index.html";

if(description)
{
  script_id(900159);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-21 15:08:20 +0200 (Tue, 21 Oct 2008)");
  script_cve_id("CVE-2008-4729");
 script_bugtraq_id(31783);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Hummingbird HostExplorer ActiveX Control BOF Vulnerability");
  script_summary("Check for vulnerable version of Hummingbird HostExplorer ActiveX Control");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/6761");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32319/");

  script_description(desc);
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

hostExpVer = registry_get_sz(key:"SOFTWARE\Hummingbird\Event Monitoring" +
                                 "\Product Info\HostExplorer 2008" ,
                             item:"Version");
if(!hostExpVer){
  hostExpVer = registry_get_sz(key:"SOFTWARE\Hummingbird\Event Monitoring" +
                                   "\Product Info\HostExplorer 2008\HostExplorer",
                               item:"Version");
  if(!hostExpVer){
    exit(0);
  }
}

# Grep for HostExplorer 2008 version < 13.0.0.0
if(ereg(pattern:"^(([0-9]|1[0-2])(\..*)?)($|[^.0-9])", string:hostExpVer)){
  security_hole(0);
}
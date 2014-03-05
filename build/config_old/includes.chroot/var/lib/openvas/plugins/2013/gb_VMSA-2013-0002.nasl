###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2013-0002.nasl 11 2013-10-27 10:12:02Z jan $
#
# VMSA-2013-0002 VMware ESX, Workstation, Fusion, and View VMCI privilege escalation vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "The remote ESXi is missing one or more security related Updates from VMSA-2013-0002.";
tag_insight = "VMware ESX, Workstation, Fusion, and View address a vulnerability in the VMCI.SYS driver which
could result in a privilege escalation on Windows-based hosts and on Windows-based Guest
Operating Systems.

Relevant releases
VMware Workstation 9.0
VMware Workstation 8.x prior to version 8.0.5
VMware Fusion 5.x prior to version 5.0.2
VMware Fusion 4.x prior to version 4.1.4
VMware View 5.x prior to version 5.1.2
VMware View 4.x prior to version 4.6.2
VMware ESXi 5.1 without ESXi510-201212102-SG
VMware ESXi 5.0 without ESXi500-201212102-SG
VMware ESXi 4.1.without ESXi410-201211402-BG
VMware ESXi 4.0 without ESXi400-201302402-SG
VMware ESX 4.1.without ESX410-201211401-SG
VMware ESX 4.0 without ESX400-201302401-SG 

Problem Description

a. VMware VMCI privilege escalation

VMware ESX, Workstation, Fusion, and View contain a vulnerability in the
handling of control code in vmci.sys. A local malicious user may exploit this
vulnerability to manipulate the memory allocation through the Virtual Machine
Communication Interface (VMCI) code. This could result in a privilege escalation
on Windows-based hosts and on Windows-based Guest Operating Systems.

The vulnerability does not allow for privilege escalation from the Guest
Operating System to the host (and vice versa). This means that host memory can
not be manipulated from the Guest Operating System (and vice versa).

Systems that have VMCI disabled are also affected by this issue.

Solution
Apply the missing patch(es).";



if (description)
{
 script_id(103662);
 script_cve_id("CVE-2013-1406");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 11 $");
 script_name("VMSA-2013-0002  VMware ESX, Workstation, Fusion, and View VMCI privilege escalation vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight;


 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-02-14 10:04:01 +0100 (Thu, 14 Feb 2013)");
 script_description(desc);
 script_summary("Checks for installed patches.");
 script_category(ACT_GATHER_INFO);
 script_family("VMware Local Security Checks");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_vmware_esxi_init.nasl");
 script_require_keys("VMware/ESXi/LSC","VMware/ESX/version");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
 }
 script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2013-0002.html");
 exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(!esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.0.0","ESXi400-201302402-SG",
                     "4.1.0","ESXi410-201301401-SG",
                     "5.0.0","VIB:esx-base:5.0.0-1.25.912577",
                     "5.1.0","VIB:tools-light:5.1.0-0.8.911593");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {

  security_hole(port:0);
  exit(0);

}

exit(99);

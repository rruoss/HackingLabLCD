###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2012-0018.nasl 12 2013-10-27 11:15:33Z jan $
#
# VMSA-2012-0018: VMware security updates for vCSA and ESXi
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
tag_solution = "Apply the missing patch(es).

See Also:
http://www.vmware.com/security/advisories/VMSA-2012-0018.html";

tag_summary = "The remote ESXi is missing one or more security related Updates from VMSA-2012-0018.

Summary
VMware has updated vCenter Server Appliance (vCSA) and ESX to address multiple security vulnerabilities

Relevant releases
vCenter Server Appliance 5.1 prior to vCSA 5.1.0b
vCenter Server Appliance 5.0 prior to vCSA 5.0 Update 2

VMware ESXi 5.1 without patch ESXi510-201212101
VMware ESXi 5.0 without patch ESXi500-201212101

Problem Description
a. vCenter Server Appliance directory traversal

The vCenter Server Appliance (vCSA) contains a directory traversal vulnerability that allows an
authenticated remote user to retrieve arbitrary files.  Exploitation of this issue may expose
sensitive information stored on the server. 

b. vCenter Server Appliance arbitrary file download

The vCenter Server Appliance (vCSA) contains an XML parsing vulnerability that allows an
authenticated remote user to retrieve arbitrary files.  Exploitation of this issue may
expose sensitive information stored on the server. 

c. Update to ESX glibc package

The ESX glibc package is updated to version glibc-2.5-81.el5_8.1 to resolve multiple security issues.";


if (description)
{
 script_id(103627);
 script_cve_id("CVE-2012-6324","CVE-2012-6325","CVE-2009-5029","CVE-2009-5064","CVE-2010-0830","CVE-2011-1089","CVE-2011-4609","CVE-2012-0864","CVE-2012-3404","CVE-2012-3405","CVE-2012-3406","CVE-2012-3480");
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 12 $");
 script_name("VMSA-2012-0018: VMware security updates for vCSA and ESXi");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-12-27 10:42:13 +0100 (Thu, 27 Dec 2012)");
 script_description(desc);
 script_summary("Checks for installed patches.");
 script_category(ACT_GATHER_INFO);
 script_family("VMware Local Security Checks");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_vmware_esxi_init.nasl");
 script_require_keys("VMware/ESXi/LSC","VMware/ESX/version");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("5.0.0","VIB:esx-base:5.0.0-1.25.912577",
                     "5.1.0","VIB:esx-base:5.1.0-0.8.911593"); 

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {

  security_hole(port:0);
  exit(0);

}

exit(99);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2012-0012.nasl 12 2013-10-27 11:15:33Z jan $
#
# VMSA-2012-0012 VMware ESXi update addresses several security issues.
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
tag_summary = "The remote ESXi is missing one or more security related Updates from VMSA-2012-0012.

Summary
VMware ESXi update addresses several security issues.

Relevant releases
ESX 5.0 without patch ESXi500-201207101-SG
ESXi 4.1 without patch ESXi410-201208101-SG

Problem Description

a. ESXi update to third party component libxml2

The libxml2 third party library has been updated which addresses multiple security issues.

Solution
Apply the missing patch(es).";


if (description)
{
 script_id(103517);
 script_cve_id("CVE-2010-4008","CVE-2010-4494","CVE-2011-0216","CVE-2011-1944","CVE-2011-2821","CVE-2011-2834","CVE-2011-3905","CVE-2011-3919","CVE-2012-0841");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 12 $");
 script_name("VMSA-2012-0012 VMware ESXi update addresses several security issues.");

desc = "
 Summary:
 " + tag_summary;


 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-07-13 17:02:01 +0100 (Fri, 13 Jul 2012)");
 script_description(desc);
 script_summary("Checks for installed patches.");
 script_category(ACT_GATHER_INFO);
 script_family("VMware Local Security Checks");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_vmware_esxi_init.nasl");
 script_require_keys("VMware/ESXi/LSC","VMware/ESX/version");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2012-0012.html");
 exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("5.0.0","VIB:esx-base:5.0.0-1.18.768111",
                     "4.0.0","ESXi400-201209401-SG",
                     "4.1.0","ESXi410-201208101-SG");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {

  security_hole(port:0);
  exit(0);

}

exit(99);

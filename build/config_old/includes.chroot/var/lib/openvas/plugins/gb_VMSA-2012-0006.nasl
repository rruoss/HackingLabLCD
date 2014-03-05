###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2012-0006.nasl 12 2013-10-27 11:15:33Z jan $
#
# VMSA-2012-0006 VMware ESXi and ESX address several security issues
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
tag_summary = "The remote ESXi is missing one or more security related Updates from VMSA-2012-0006.

Summary
VMware ESXi and ESX address several security issues.

Relevant releases

ESXi 4.1 without patch ESXi410-201101201-SG
ESXi 4.0 without patch ESXi400-201203401-SG
ESXi 3.5 without patch ESXe350-201203401-I-SG
ESX 4.1 without patch ESX410-201101201-SG
ESX 4.0 without patches ESX400-201203401-SG, ESX400-201203407-SG
ESX 3.5 without patch ESX350-201203401-SG

Problem Description

a. VMware ROM Overwrite Privilege Escalation

A flaw in the way port-based I/O is handled allows for modifying Read-Only
Memory that belongs to the Virtual DOS Machine. Exploitation of this issue may
lead to privilege escalation on Guest Operating Systems that run Windows 2000,
Windows XP 32-bit, Windows Server 2003 32-bit or Windows Server 2003 R2
32-bit.

b. ESX third party update for Service Console kernel

The ESX Service Console Operating System (COS) kernel is updated to
kernel-400.2.6.18-238.4.11.591731 to fix multiple security issues in the COS
kernel.

c. ESX third party update for Service Console krb5 RPM

This patch updates the krb5-libs and krb5-workstation RPMs to version
1.6.1-63.el5_7 to resolve a security issue.

Solution
Apply the missing patch(es).";


if (description)
{
 script_id(103458);
 script_cve_id("CVE-2012-1515","CVE-2011-2482","CVE-2011-3191","CVE-2011-4348","CVE-2011-4862");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 12 $");
 script_name("VMSA-2012-0006 VMware ESXi and ESX address several security issues");

desc = "
 Summary:
 " + tag_summary;



 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-04-02 10:53:01 +0100 (Mon, 02 Apr 2012)");
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
 script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2012-0006.html");
 exit(0);
}

include("vmware_esx.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.1.0","ESXi410-201101201-SG",
                     "4.0.0","ESXi400-201203401-SG");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {

  security_hole(port:0);
  exit(0);

}

exit(99);

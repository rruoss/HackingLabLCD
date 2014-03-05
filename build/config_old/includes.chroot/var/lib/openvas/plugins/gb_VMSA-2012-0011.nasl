###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2012-0011.nasl 12 2013-10-27 11:15:33Z jan $
#
# VMSA-2012-0011 VMware Workstation, Player, Fusion, ESXi and ESX patches address security issues.
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
tag_summary = "The remote ESXi is missing one or more security related Updates from VMSA-2012-0011.

Summary
VMware Workstation, Player, Fusion, ESXi and ESX patches address security issues.

Relevant releases:

Workstation 8.0.3
Workstation 7.1.5

Player 4.0.3
Player 3.1.5

Fusion 4.1.2

ESXi 5.0 without patch ESXi500-201206401-SG
ESXi 4.1 without patch ESXi410-201206401-SG
ESXi 4.0 without patch ESXi400-201206401-SG
ESXi 3.5 without patch ESXe350-201206401-I-SG

ESX 4.1 without patch ESX410-201206401-SG
ESX 4.0 without patch ESX400-201206401-SG
ESX 3.5 without patch ESX350-201206401-SG

Problem Description

a. VMware Host Checkpoint file memory corruption

Input data is not properly validated when loading Checkpoint files. This may
allow an attacker with the ability to load a specially crafted Checkpoint file
to execute arbitrary code on the host.

VMware would like to thank Thorsten T�llmann for reporting this issue to us.

Workaround - None identified

Mitigation - Do not import virtual machines from untrusted sources.

b. VMware Virtual Machine Remote Device Denial of Service

A device (e.g. CD-ROM, keyboard) that is available to a virtual machine while
physically connected to a system that does not run the virtual machine is
referred to as a remote device.

Traffic coming from remote virtual devices is incorrectly handled. This may
allow an attacker who is capable of manipulating the traffic from a remote
virtual device to crash the virtual machine.

Workaround - None identified

Mitigation - Users need administrative privileges on the virtual machine in
order to attach remote devices. - Do not attach untrusted remote devices to a
virtual machine.

Solution
Apply the missing patch(es).";


if (description)
{
 script_id(103495);
 script_cve_id("CVE-2012-3288", "CVE-2012-3289");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 12 $");
 script_name("VMSA-2012-0011 VMware Workstation, Player, Fusion, ESXi and ESX patches address security issues.");

desc = "
 Summary:
 " + tag_summary;


 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-06-15 10:02:01 +0100 (Fri, 15 June 2012)");
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
 script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2012-0011.html");
 exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.1.0","ESXi410-201206401-SG",
                     "4.0.0","ESXi400-201206401-SG",
                     "5.0.0","VIB:esx-base:5.0.0-1.16.721882");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {

  security_hole(port:0);
  exit(0);

}

exit(99);

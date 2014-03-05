###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2013-0011.nasl 11 2013-10-27 10:12:02Z jan $
#
# VMSA-2013-0011 VMware ESX and ESXi updates to third party libraries
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

tag_summary = "VMware has updated VMware ESXi and ESX to address a vulnerability in
an unhandled exception in the NFC protocol handler.";

tag_solution = "Apply the missing patch(es).";

tag_affected = "VMware ESXi 5.1 without patch ESXi510-201307101
VMware ESXi 5.0 without patch ESXi500-201308101     
VMware ESXi 4.1 without patch ESXi410-201304401
VMware ESXi 4.0 without patch ESXi400-201305401

VMware ESX 4.1 without patch ESX410-201304401
VMware ESX 4.0 without patch ESX400-201305401";

tag_vuldetect = "Check if the patch for VMSA-2013-0011 is installed.";

tag_insight = "VMware ESXi and ESX NFC Protocol Unhandled Exception

VMware ESXi and ESX contain a vulnerability in the handling of
the Network File Copy (NFC) protocol. To exploit this
vulnerability, an attacker must intercept and modify the NFC
traffic between ESXi/ESX and the client.  Exploitation of the
issue may lead to a Denial of Service.

To reduce the likelihood of exploitation, vSphere components should
be deployed on an isolated management network";

if (description)
{
 script_id(103778);
 script_cve_id("CVE-2013-1661");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_version ("$Revision: 11 $");
 script_name("VMSA-2013-0011 VMware ESX and ESXi updates to third party libraries");

 desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

 script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2013-0011.html");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-09-02 14:04:01 +0100 (Mon, 02 Sep 2013)");
 script_description(desc);
 script_summary("Checks for installed patches.");
 script_category(ACT_GATHER_INFO);
 script_family("VMware Local Security Checks");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_vmware_esxi_init.nasl");
 script_require_keys("VMware/ESXi/LSC","VMware/ESX/version");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "vuldetect" , value : tag_vuldetect);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "affected" , value : tag_affected);
 }

 exit(0);

}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(!esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.0.0","ESXi400-201305401-SG",
                     "4.1.0","ESXi410-201304401-SG",
                     "5.0.0","VIB:tools-light:5.0.0-2.35.1254542",
                     "5.1.0","VIB:tools-light:5.1.0-1.16.1157734");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {

  security_warning(port:0);
  exit(0);

}

exit(99);








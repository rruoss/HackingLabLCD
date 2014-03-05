###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2013-0009.nasl 11 2013-10-27 10:12:02Z jan $
#
# VMSA-2013-0009 VMware ESX and ESXi updates to third party libraries
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

tag_summary = "VMware has updated several third party libraries in ESX and ESXi to address multiple security vulnerabilities.";
tag_solution = "Apply the missing patch(es).";

tag_affected = "VMware ESXi 4.1 without patch ESXi410-201307001. 
VMware ESX 4.1 without patch ESX410-201307001";

tag_vuldetect = "Check if Bulletin ESXi410-201307001 is installed.";

tag_insight = "a. ESX userworld update for OpenSSL library
The userworld OpenSSL library is updated to version openssl-0.9.8y to resolve
multiple security issues.

b. Service Console (COS) update for OpenSSL library
The Service Console updates for OpenSSL library is updated to version
openssl-0.9.8e-26.el5_9.1 to resolve multiple security issues.

c. ESX Userworld and Service Console (COS) update for libxml2 library
The ESX Userworld and Service Console libxml2 library is updated to version
libxml2-2.6.26-2.1.21.el5_9.1 and libxml2-python-2.6.26-2.1.21.el5_9.1. to
resolve a security issue. 

d. Service Console (COS) update for GnuTLS library
The ESX service console GnuTLS RPM is updated to version
gnutls-1.4.1-10.el5_9.1 to resolve a security issue.

e. ESX third party update for Service Console kernel
The ESX Service Console Operating System (COS) kernel is updated to
kernel-2.6.18-348.3.1.el5 which addresses several security issues in the COS
kernel.";


if (description)
{
 script_id(103749);
 script_cve_id("CVE-2013-0169","CVE-2013-0166","CVE-2013-0338","CVE-2013-2116","CVE-2013-0268","CVE-2013-0871");
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 11 $");
 script_name("VMSA-2013-0009 VMware ESX and ESXi updates to third party libraries");

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

 script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2013-0009.html");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-07 14:04:01 +0100 (Wed, 07 Aug 2013)");
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

patches = make_array("4.1.0","ESXi410-201307401-SG");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {

  security_hole(port:0);
  exit(0);

}

exit(99);








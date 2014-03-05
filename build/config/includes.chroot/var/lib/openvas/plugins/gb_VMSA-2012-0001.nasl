###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2012-0001.nasl 12 2013-10-27 11:15:33Z jan $
#
# VMSA-2012-0001 VMware ESXi and ESX updates to third party library and ESX Service Console
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
tag_summary = "The remote ESXi is missing one or more security related Updates from VMSA-2012-0001.

Summary

VMware ESXi and ESX updates to third party library and ESX Service Console address
several security issues.

Relevant releases:

ESXi 4.1 without patch ESXi410-201201401-SG
ESXi 5.0 without patch ESXi500-201203101-SG
ESXi 4.0 without patch ESXi400-201203401-SG

ESX 4.1 without patches ESX410-201201401-SG, ESX410-201201402-SG,
ESX410-201201404-SG, ESX410-201201405-SG, ESX410-201201406-SG,
ESX410-201201407-SG.
  
Problem Description

a. ESX third party update for Service Console kernel

   The ESX Service Console Operating System (COS) kernel is updated to kernel-2.6.18-274.3.1.el5
   to fix multiple security issues in the COS kernel.
   
b. ESX third party update for Service Console cURL RPM

   The ESX Service Console (COS) curl RPM is updated to cURL-7.15.5.9 resolving a security issue.

c. ESX third party update for Service Console nspr and nss RPMs

   The ESX Service Console (COS) nspr and nss RPMs are updated to nspr-4.8.8-1.el5_7 and
   nss-3.12.10-4.el5_7 respectively resolving a security issue.

   A Certificate Authority (CA) issued fraudulent SSL certificates and Netscape
   Portable Runtime (NSPR) and Network Security Services (NSS) contain the
   built-in tokens of this fraudulent Certificate Authority. This update renders
   all SSL certificates signed by the fraudulent CA as untrusted for all uses.

d. ESX third party update for Service Console rpm RPMs

   The ESX Service Console Operating System (COS) rpm packages are updated to
   popt-1.10.2.3-22.el5_7.2, rpm-4.4.2.3-22.el5_7.2, rpm-libs-4.4.2.3-22.el5_7.2
   and rpm-python-4.4.2.3-22.el5_7.2 which fixes multiple security issues.

e. ESX third party update for Service Console samba RPMs

   The ESX Service Console Operating System (COS) samba packages are updated to
   samba-client-3.0.33-3.29.el5_7.4, samba-common-3.0.33-3.29.el5_7.4 and
   libsmbclient-3.0.33-3.29.el5_7.4 which fixes multiple security issues in the
   Samba client.

f. ESX third party update for Service Console python package

   The ESX Service Console (COS) python package is updated to 2.4.3-44 which fixes
   multiple security issues.

g. ESXi update to third party component python

   The python third party library is updated to python 2.5.6 which fixes multiple
   security issues.";

tag_solution = "Apply the missing patch(es).";

if (description)
{
 script_id(103448);
 script_cve_id("CVE-2009-3560", "CVE-2009-3720", "CVE-2010-0547", "CVE-2010-0787", "CVE-2010-1634", "CVE-2010-2059", "CVE-2010-2089", "CVE-2010-3493", "CVE-2010-4649", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-0726", "CVE-2011-1015", "CVE-2011-1044", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1093", "CVE-2011-1163", "CVE-2011-1166", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1182", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1521", "CVE-2011-1573", "CVE-2011-1576", "CVE-2011-1577", "CVE-2011-1593", "CVE-2011-1678", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1763", "CVE-2011-1776", "CVE-2011-1780", "CVE-2011-1936", "CVE-2011-2022", "CVE-2011-2192", "CVE-2011-2213", "CVE-2011-2482", "CVE-2011-2491", "CVE-2011-2492", "CVE-2011-2495", "CVE-2011-2517", "CVE-2011-2519", "CVE-2011-2522", "CVE-2011-2525", "CVE-2011-2689", "CVE-2011-2694", "CVE-2011-2901", "CVE-2011-3378");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 12 $");
 script_name("VMSA-2012-0001 VMware ESXi and ESX updates to third party library and ESX Service Console");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-03-15 14:13:01 +0100 (Thu, 15 Mar 2012)");
 script_description(desc);
 script_summary("Checks for installed patches.");
 script_category(ACT_GATHER_INFO);
 script_family("VMware Local Security Checks");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_vmware_esxi_init.nasl");
 script_require_keys("VMware/ESXi/LSC","VMware/ESX/version");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2012-0001.html");
 exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.1.0", "ESXi410-201201401-SG",
                     "4.0.0", "ESXi400-201203401-SG",
                     "5.0.0", "VIB:esx-base:5.0.0-0.10.608089");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {

  security_hole(port:0);
  exit(0);

}

exit(99);








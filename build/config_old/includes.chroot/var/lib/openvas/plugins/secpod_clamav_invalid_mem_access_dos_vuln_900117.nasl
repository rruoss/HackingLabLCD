##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_clamav_invalid_mem_access_dos_vuln_900117.nasl 16 2013-10-27 13:09:52Z jan $
# Description: ClamAV Invalid Memory Access Denial Of Service Vulnerability 
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
tag_impact = "Successful remote exploitation will allow attackers to cause
        the application to crash.

 Impact Level : Application";

tag_solution = "Upgrade to ClamAV version 0.94
 http://www.clamav.net/download/sources";

tag_affected = "ClamAV versions prior to ClamAV 0.94 on all platform.";

tag_insight = "The flaw exists due to an invalid memory access in chmunpack.c file,
        when processing a malformed CHM file.";

tag_summary = "The host is running Clam AntiVirus, which is prone to denial of
 service vulnerability.";



if(description)
{
 script_id(900117);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-05 16:50:44 +0200 (Fri, 05 Sep 2008)");
 script_bugtraq_id(30994);
 script_cve_id("CVE-2008-1389");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_name("ClamAV Invalid Memory Access Denial Of Service Vulnerability");
 script_summary("Check for vulnerable version of ClamAV");
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

 script_description(desc);
 script_dependencies("gather-package-list.nasl");
 script_require_keys("ssh/login/uname");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "impact" , value : tag_impact);
 }
 script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2484");
 script_xref(name : "URL" , value : "http://svn.clamav.net/svn/clamav-devel/trunk/ChangeLog");
 exit(0);
}


 include("ssh_func.inc");

 if("Linux" >!< get_kb_item("ssh/login/uname")){
        exit(0);
 }
 
 foreach item (get_kb_list("ssh/*/rpms"))
 {
        if("clamav~" >< item)
        {
                if(egrep(pattern:"^clamav~0\.([0-8]?[0-9]|9[0-3])($|[^0-9])",
                         string:item))
		{
                        security_warning(0); 
		        exit(0);
                }
        }
 }

 sock = ssh_login_or_reuse_connection();
 if(!sock){
        exit(0);
 }

 clamVer = ssh_cmd(socket:sock, cmd:"clamav-config --version", timeout:timeout);
 ssh_close_connection();

 if(!clamVer){
        exit(0);
 }

 if(egrep(pattern:"^0\.([0-8]?[0-9]|9[0-3])($|[^0-9])", string:clamVer)){
        security_warning(port);
 }

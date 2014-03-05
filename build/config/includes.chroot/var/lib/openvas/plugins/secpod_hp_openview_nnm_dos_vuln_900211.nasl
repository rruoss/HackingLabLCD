##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_openview_nnm_dos_vuln_900211.nasl 16 2013-10-27 13:09:52Z jan $
# Description: HP OpenView Network Node Manager Denial of Service Vulnerabilities
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation can cause application to crash.
 Impact Level : Application";

tag_solution = "Apply patches from,
 http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01537275 

 *****
 NOTE : Ignore this warning, if above mentioned patch is already applied.
 *****";

tag_affected = "HP OpenView Network Node Manager (OV NNM) v7.01, v7.51, v7.53.";

tag_insight = "Flaws are due to an errors in ovalarmsrv program.";


tag_summary = "This host is running HP OpenView Network Node Manager, which is
 prone to Denial of Service vulnerabilities.";


if(description)
{
 script_id(900211);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-05 16:50:44 +0200 (Fri, 05 Sep 2008)");
 script_bugtraq_id(30984);
 script_cve_id("CVE-2008-3536", "CVE-2008-3537");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_name("HP OpenView Network Node Manager Denial of Service Vulnerabilities");
 script_summary("Check for version of HP OpenView Network Node Manager");
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
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31688/");
 script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2485");
 script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01537275");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "impact" , value : tag_impact);
 }
 exit(0);
}


 include("http_func.inc");
 include("http_keepalive.inc");

 nnmPort = 7510;
 if(get_port_state(nnmPort))
 {
        nnmReq = http_get(item:"/topology/home", port:nnmPort);
        nnmRes = http_keepalive_send_recv(port:nnmPort, data:nnmReq);

        if("Network Node Manager Home Base" >< nnmRes &&
           egrep(pattern:"Copyright \(c\).* Hewlett-Packard", string:nnmRes) &&
           ereg(pattern:"^HTTP/.* 200 OK", string:nnmRes))
        {
        	if(egrep(pattern:"NNM Release B\.07\.(01|51|53)[^0-9]",
                         string:nnmRes)){
                        security_hole(nnmPort);
                }
                exit(0);
         }
 }

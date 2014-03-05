##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_softalk_mail_serv_imap_dos_vuln_900119.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Softalk Mail Server IMAP Denial of Service Vulnerability
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
tag_impact = "Successful exploitation crashes the affected server denying the
        service to legitimate users.

 Impact Level : Application";

tag_solution = "Upgrade to Softalk Mail Server version 8.6.0 or later,
 For updates refer to http://www.softalkltd.com/products/download_wm.asp";

tag_affected = "Softalk Mail Server versions 8.5.1 and prior on Windows (all)";

tag_insight = "The issue is due to inadequate boundary checks on specially 
        crafted IMAP commands. The service can by crashed sending malicious 
        IMAP command sequences.";

tag_summary = "The host is running Softalk Mail Server, which is prone to denial
 of service vulnerability.";



if(description)
{
 script_id(900119);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)");
 script_cve_id("CVE-2008-4041");
 script_bugtraq_id(30970);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_name("Softalk Mail Server IMAP Denial of Service Vulnerability");
 script_summary("Check for vulnerable version of Softalk");
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
 script_dependencies("find_service.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "impact" , value : tag_impact);
 }
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31715/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/495896");
 exit(0);
}


 include("imap_func.inc");

 port = get_kb_item("Services/imap");
 if(!port){
        port = 143;
 }

 if(!get_port_state(port)) {
        exit(0);
 }
 
 banner = get_imap_banner(port); 
 if(!banner){
        exit(0);
 }

 if(egrep(pattern:"Softalk Mail Server ([0-7]\..*|8\.([0-4](\..*)?|5(\.0" +
                      "(\..*)?)?|5\.1))[^.0-9]", string:banner)){
        security_warning(port);
 }

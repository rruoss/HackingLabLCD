##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hmailserver_imap_dos_vuln_900109.nasl 16 2013-10-27 13:09:52Z jan $
# Description: hMailServer IMAP Denial of Service Vulnerability
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
tag_impact = "Exploitation will cause the server to crash and deny access
        to legitimate users.
 Impact Level : Application/System";

tag_solution = "Fixed in development version 4.4.2 (build 279)
 http://www.hmailserver.com/?page=download_mirrors&downloadid=144";

tag_affected = "hMailServer version 4.4.1 - Build 273 and prior";

tag_insight = "The flaw is due to an error in the mail server that can be exploited 
        by sending large numbers of IMAP commands.";


tag_summary = "This host is running hMailServer, which is prone to
 Denial of Service vulnerability.";


if(description)
{
 script_id(900109);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_cve_id("CVE-2008-3676");
 script_bugtraq_id(30663);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_name("hMailServer IMAP Denial of Service Vulnerability");
 script_summary("Check for vulnerable version of hMailServer");
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
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/495361");
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31480/");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "impact" , value : tag_impact);
 }
 exit(0);
}


 include("smb_nt.inc");
 include("imap_func.inc");
 
 port = get_kb_item("Services/imap");
 if(!port) {
	port = 143;
 }

 if(!get_port_state(port)) {
	exit(0);
 }

 if("IMAP" >!< get_imap_banner(port:port)){
        exit(0);
 }

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 hmsVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion"
					+ "\Uninstall\hMailServer_is1",
			  item:"DisplayName");
 if(!hmsVer){
	exit(0);
 } 

 if(egrep(pattern:"hMailServer ([0-3]\..*|4\.([0-3]\..*|4\.[01]))", string:hmsVer)){
	security_warning(port);
 }

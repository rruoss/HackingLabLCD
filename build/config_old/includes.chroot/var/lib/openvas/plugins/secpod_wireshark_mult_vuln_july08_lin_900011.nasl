##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wireshark_mult_vuln_july08_lin_900011.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Wireshark Multiple Vulnerabilities - July08 (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
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
tag_impact = "Successful exploitation could result in application crash,
	disclose of system memory, and an incomplete syslog encapsulated
	packets.
 Impact Level : SYSTEM";

tag_affected = "Wireshark versions prior to 1.0.1 on Linux (All).
 
 Quick Fix : Disable the following dissectors,
 GSM SMS, PANA, KISMET, RTMPT, and RMI";

tag_insight = "The flaws exists due to errors in GSM SMS dissector, PANA and KISMET
	dissectors, RTMPT dissector, RMI dissector, and in syslog dissector.";


tag_summary = "The host is running Wireshark/Ethereal, which is prone to multiple
 vulnerabilities.";

tag_solution = "Upgrade to wireshark to 1.0.1 or later.
 http://www.wireshark.org/download.html";


if(description)
{
 script_id(900011);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_bugtraq_id(28485);
 script_cve_id("CVE-2008-1561", "CVE-2008-1562", "CVE-2008-1563");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_name("Wireshark Multiple Vulnerabilities - July08 (Linux)");
 script_summary("Check for vulnerable version of Wireshark/Ethereal");
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
 " + tag_solution; script_description(desc);
 script_dependencies("gather-package-list.nasl");
 script_require_keys("ssh/login/uname");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "impact" , value : tag_impact);
 }
 exit(0);
}


 include("ssh_func.inc");

 if("Linux" >!< get_kb_item("ssh/login/uname")){
        exit(0);
 }

 foreach item (get_kb_list("ssh/*/rpms"))
 {
        if("ethereal" >< item)
	{
        	security_hole(0);
		exit(0);
        }

	else if("wireshark" >< item)
	{
		if(egrep(pattern:"wireshark~(0\.99\.[1-9]|1\.0\.0)($|[^.0-9])",
			 string:item))
                {
                        security_hole(0);
                        exit(0);
                }
        }
 }

 sock = ssh_login_or_reuse_connection();
 if(!sock){
	exit(0);
 }

 etherealVer = ssh_cmd(socket:sock, cmd:"ethereal -v", timeout:120);
 if("Compiled" >< etherealVer)
 {
	if(egrep(pattern:"ethereal 0\.([0-8]?[0-9]\..*|9[0-8]\..*|99\.0)$",
          	 string:etherealVer)){
        	security_warning(0);
 	}
 }

 wiresharkVer = ssh_cmd(socket:sock, cmd:"wireshark -v", timeout:120);
 ssh_close_connection();

 if("Compiled" >< wiresharkVer)
 {
	if(egrep(pattern:"wireshark (0\.99\.[1-9]|1.0.0)$", string:wiresharkVer)){
		security_hole(0);
	}
 }

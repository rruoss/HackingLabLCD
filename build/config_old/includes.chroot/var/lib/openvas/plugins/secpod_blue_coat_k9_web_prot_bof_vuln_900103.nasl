##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_blue_coat_k9_web_prot_bof_vuln_900103.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Blue Coat K9 Web Protection Multiple Buffer Overflow Vulnerabilities
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
tag_impact = "Successful exploitation could allow remote attackers to cause
        stack based buffer overflow by sending specially crafted malicious
        code containing and overly long http version information and
        reference header.
 Impact Level : System";

tag_solution = "No solution or patch is available as of 01st August, 2008. Solution details
 will be updated soon once the details are available. For update refer,
 http://www1.k9webprotection.com/aboutk9/index.php";

tag_affected = "Blue Coat K9 Web Protection versions 3.2.44 and prior on Windows (All)";

tag_insight = "The flaws exist due to errors in filter services (k9filter.exe) when
        handling,
        - http version information in responses from a centralised server
          (sp.cwfservice.net).
        - Referer: headers during access to the web-based K9 Web Protection
          Administration interface.";


tag_summary = "This host is installed with Blue Coat K9 Web Protection, which is
 prone to stack based buffer overflow vulnerability.";


if(description)
{
 script_id(900103);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_bugtraq_id(30464,30463);
 script_cve_id("CVE-2007-2752");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_tag(name:"risk_factor", value:"High");
 script_category(ACT_GATHER_INFO);
 script_family("Buffer overflow");
 script_name("Blue Coat K9 Web Protection Multiple Buffer Overflow Vulnerabilities");
 script_summary("Check for vulnerable version and prior of Blue Coat");
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
 script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2007-61/advisory/");
 script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2007-64/advisory/");
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

 if (!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 blueVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
			       "\Uninstall\Blue Coat K9 Web Protection",
			   item:"DisplayVersion");
 
 if(egrep(pattern:"^([0-2]\..*|3\.([01]\..*|2\.([0-3]?[0-9]|4[0-4])))$",
	  string:blueVer)) {
	security_hole(0);
 }

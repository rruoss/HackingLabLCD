##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mysql_dos_vuln_900221.nasl 16 2013-10-27 13:09:52Z jan $
# Description: MySQL Empty Bit-String Literal Denial of Service Vulnerability
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
tag_impact = "Successful exploitation by remote attackers could cause denying
        access to legitimate users.
 Impact Level : Application";

tag_solution = "Update to version 5.0.66 or 5.1.26 or 6.0.6 or later.
 http://dev.mysql.com/downloads/";

tag_affected = "MySQL versions prior to 5.0.x - 5.0.66,
                                5.1.x - 5.1.26, and
                                6.0.x - 6.0.5 on all running platform.";

tag_insight = "Issue is due to error while processing an empty bit string literal via
        a specially crafted SQL statement.";


tag_summary = "This host is running MySQL, which is prone to Denial of Service
 Vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900221";
CPE = "cpe:/a:mysql:mysql";

if(description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
 script_bugtraq_id(31081);
 script_cve_id("CVE-2008-3963");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_name("MySQL Empty Bit-String Literal Denial of Service Vulnerability");
 script_summary("Check for version of MySQL");
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
 script_dependencies("mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 script_require_keys("MySQL/installed");
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31769/");
 script_xref(name : "URL" , value : "http://bugs.mysql.com/bug.php?id=35658");
 script_xref(name : "URL" , value : "http://dev.mysql.com/doc/refman/5.1/en/news-5-1-26.html");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "impact" , value : tag_impact);
 }
 exit(0);
}


 include("misc_func.inc");
 include("host_details.inc");


 sqlPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
 if(!sqlPort){
        sqlPort = 3306;
 }

 if(!get_port_state(sqlPort)){
        exit(0);
 }

 mysqlVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:sqlPort);

 if(mysqlVer)
 {
       # grep for version < 5.0.66, 5.1.26, and 6.0.6
       if(ereg(pattern:"^(5\.0(\.[0-5]?[0-9]|\.6[0-5])?|5\.1(\.[01]?[0-9]|" +
                       "\.2[0-5])?|6\.0(\.[0-5])?)[^.0-9]", string:mysqlVer)){
                security_warning(sqlPort);
       }
 }

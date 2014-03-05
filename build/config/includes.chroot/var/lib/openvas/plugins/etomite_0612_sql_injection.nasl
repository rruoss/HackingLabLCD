# OpenVAS Vulnerability Test
# $Id: etomite_0612_sql_injection.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Etomite CMS id Paramater SQL Injection
#
# Authors:
# Justin Seitz <jms@bughunter.ca>
#
# Copyright:
# Copyright (C) 2006 Justin Seitz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote web server contains a PHP script that is affected by a SQL
injection vulnerability. 

Description:

The remote web server is running Etomite CMS, a PHP-based content
management system. 

The version of Etomite CMS installed on the remote host fails to
sanitize input to the 'id' parameter before using it in the
'index.php' script in a database query.  Provided PHP's
'magic_quotes_gpc' setting is disabled, an unauthenticated attacker
can exploit this issue to manipulate SQL queries, possibly leading to
disclosure of sensitive data, attacks against the underlying database,
and the like.";

tag_solution = "No patches or upgrades have been reported by the vendor at this time.";

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 # set script identifiers

 script_id(80057);;
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_cve_id("CVE-2006-6048");
 script_bugtraq_id(21135);
 script_xref(name:"OSVDB", value:"30442");

 name = "Etomite CMS id Paramater SQL Injection";
 summary = "Tries to generate a SQL error with Etomite CMS";
 family = "Web application abuses";

 script_name(name);
 script_description(desc);
 script_summary(summary);

 script_category(ACT_ATTACK);
 script_copyright("This script is Copyright (C) 2006 Justin Seitz");

 script_family(family);

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/451838/30/0/threaded");
 exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
port = get_http_port(default:80);

#
# verify we can talk to the web server, if not exit
#

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);

#
# create list of directories to scan
#


# Loop through directories.

if (thorough_tests) dirs = make_list("/etomite","/cms", cgi_dirs());
else dirs = make_list(cgi_dirs());

#
# Iterate through the list
#

injectstring = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_", length:10);

foreach dir (dirs) {

	#
	#
	#       Attack: Attempt to inject our random string.
	#
	#
	
	attackreq = http_get(item:string(dir, "/index.php?id=", injectstring, "'"),port:port);
	attackres = http_keepalive_send_recv(port:port, data:attackreq, bodyonly:TRUE);
	if (attackres == NULL) exit(0);
	
	sqlstring = "";
	if(string("etomite_site_content.id = '", injectstring) >< attackres) {
            if (report_verbosity > 1) {
			sqlstring = attackres;
			if("<span id='sqlHolder'>" >< sqlstring) sqlstring = strstr(sqlstring,"SELECT");
			
			if("</span></b>" >< sqlstring) sqlstring = sqlstring - strstr(sqlstring, "</span></b>");			


			info = string("The version of Etomite CMS installed in directory '", dir, "'\n",
	        	"is vulnerable to this issue. Here is the resulting SQL string\n",
			"from the remote host when using a test string of '",injectstring,"'  :\n\n", sqlstring);
		     	report = string(desc,"\n\nPlugin output\n\n",info);
            }
            else report = desc;

            security_hole(data:report, port:port);
	    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
            exit(0);
	}
}

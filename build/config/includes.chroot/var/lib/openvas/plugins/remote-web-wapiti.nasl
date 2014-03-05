##############################################################################
# OpenVAS Vulnerability Test
#
# Assess web security with wapiti
#
# Authors:
# Vlatko Kosturjak <kost@linux.hr>
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
###############################################################################

include("revisions-lib.inc");
tag_summary = "This plugin uses wapiti to find  
web security issues.

Make sure to have wapiti 2.x as wapiti 1.x is not supported. 

See the preferences section for wapiti options.

Note that OpenVAS is using limited set of wapiti options.
Therefore, for more complete web assessment, you should
use standalone wapiti tool for deeper/customized checks.";

if(description)
{
 script_id(80110);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-24 21:54:49 +0100 (Wed, 24 Mar 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "wapiti (NASL wrapper)";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Assess web security with wapiti";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2010 Vlatko Kosturjak");
 family = "Web application abuses";
 script_family(family);
 script_add_preference(name:"Nice", type:"entry", value:"");
 script_dependencies("find_service.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(0); 
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# main code

cmdext = "wapiti";

port = get_kb_item("Services/www");
if (! port) port = 80;
if (! get_port_state(port)) exit(0);

encaps = get_port_transport(port);
if (encaps > 1) httprefix="https://";
else httprefix="http://";

httpver = get_kb_item("http/"+port);
if (httpver == "11") {
	httparg=get_host_name();
} else {
	httparg=get_host_ip();
}

httpurl=httprefix+httparg+":"+port;

genfilename = get_tmp_dir() + "openvas-wapiti-" + get_host_ip() + "-" + port;
repfilename = genfilename + ".txt";

# display(repfilename);

function on_exit()
{
	if (file_stat (repfilename)) unlink(repfilename);
}

if (!find_in_path(cmdext)  )
{
    text = 'wapiti could not be found in your system path.\n';
    text += 'OpenVAS was unable to execute wapiti and to perform the scan you
requested.\nPlease make sure that wapiti is installed and that '+cmdext+' is
available in the PATH variable defined for your environment.';
    log_message(port: port, data: text);
    exit(0);
}

nice=script_get_preference("Nice");

i = 0;
argv[i++] = cmdext;
argv[i++] = httpurl; # URL to scan (must be first!)

# options
if (report_verbosity > 1) {
	argv[i++] = "-v"; argv[i++] = "1"; 
} else {
	argv[i++] = "-v"; argv[i++] = "0";
}

if (nice) { 
	if (nice>0) {
		argv[i++] = "-n"; argv[i++] = nice;
	}
}

argv[i++] = "-f"; argv[i++] = "txt";

argv[i++] = "-o"; argv[i++] = repfilename;

#foreach argument (argv) {
#	display(argument);
#	display(' ');
# }

r = pread(cmd: cmdext, argv: argv, cd: 1);
if (! r) exit(0);	# error

if (file_stat(repfilename)) {
	rfile=fread(repfilename);
	report='';
	if (report_verbosity > 1) {
		report += 'Here is the wapiti output:\n';
		report += r;	
	}
	report += 'Here is the wapiti report:\n';
	report += rfile;
	report += '\n--- End of report ---';
	if ('SQL Injection found' >< report) {
		security_hole(port: port, data: report);
	} else {
		security_note(port: port, data: report);
	}
} else {
	text  = 'wapiti report filename is empty. that could mean that\n';
	text += 'wrong version of wapiti is used or tmp dir is not accessible.\n';
	text += 'Make sure to have wapiti 2.x as wapiti 1.x is not supported.\n';
	text += 'In short: check installation of wapiti and OpenVAS';
	log_message(port: port, data: text);
}


###############################################################################
# OpenVAS Vulnerability Test
# $Id: find_service_nmap.nasl 43 2013-11-04 19:51:40Z jan $
#
# Nmap Supplementary Service Detection
#
# Authors:
# Thomas Reinke
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_summary = "This plugin performs service detection by launching nmap's
service probe against ports running unidentified services.

Description :

This plugin is a complement of find_service.nasl. It launches
nmap -sV (probe requests) against ports that are running
unidentified services.";

# For those who wish to go digging, please note that this is potentially
# the second time nmap will be launched with -sV (service identification)
# parameters.  The first timeout can be in "nmap.nasl". We cannot, however,
# rely on that pass for a number of reasons:
#    1. We may not be running that port scanner.
#    2. We only want to run AFTER find_service* scripts have executed,
#       along with a whole host of other specialty service identification
#       scripts. Our objective is to minimize nmap service identification
#       execution time, and only run it on services that remain unidentified
#

if(description)
{
 script_id(66286);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-11-18 19:41:26 +0100 (Wed, 18 Nov 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_name("Identify unknown services with nmap");

 desc = "
 Summary:
 " + tag_summary;
 script_description(desc);

 script_summary("Launches nmap -sV against ports running unidentified services");

 script_category(ACT_GATHER_INFO); 
 script_timeout(0);
 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Service detection");

 # The up to date list is the name of any script that contains
 # a callto 'register_service'. Unfortunately, the parameter list size
 # is maxed out where it is right now, so there are a bunch of
 # unmet dependencies. Fortunately, the only impact that has is to
 # run unnecessary nmap service probes against ports already identified
 script_dependencies(
        "toolcheck.nasl",
	"PC_anywhere_tcp.nasl",
	"SHN_discard.nasl",
	"X.nasl",
	"apcnisd_detect.nasl",
	"alcatel_backdoor_switch.nasl",
	"asip-status.nasl",
	"auth_enabled.nasl",
	"bugbear.nasl",
	"cifs445.nasl",
	"cp-firewall-auth.nasl",
	"dcetest.nasl",
	"dns_server.nasl",
	"echo.nasl",
	"find_service1.nasl",
	"find_service2.nasl",
	"mldonkey_telnet.nasl",
	"mssqlserver_detect.nasl",
	"mysql_version.nasl",
	"nessus_detect.nasl",
	"qmtp_detect.nasl",
	"radmin_detect.nasl",
	"secpod_rpc_portmap.nasl",
	"rpcinfo.nasl",
	"rsh.nasl",
	"rtsp_detect.nasl",
	"telnet.nasl",
	"xtel_detect.nasl",
	"xtelw_detect.nasl");

 # Do *not* add a port dependency on "Services/unknown"
 # Some scripts must run after this script even if there are no
 # unknown services

 if(defined_func("script_mandatory_keys"))
   script_mandatory_keys("Tools/Present/nmap");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# script_mandatory_keys compatibility:
include ("toolcheck.inc");
exit_if_not_found (toolname: "nmap");
# end of script_mandatory_keys compatibility

include("misc_func.inc");
include("global_settings.inc");

ver = pread(cmd: "nmap", argv: make_list("nmap", "-V"));
extract = eregmatch(string: ver, pattern: ".*nmap version ([0-9.]+).*", icase:TRUE);

# Only run if we have nmap 4.62 or later available.
# Yes - this is arbitrary. We've tested with 4.62 and 5.00
if(isnull(extract)) {
    exit(0);
}
if(revcomp(a:extract[1], b:"4.62")<0) {
    exit(0);
}

# This will fork.  Potential issue if large # of unknown services.
# (But then the other find_service*.nasl scripts have the same problem.
port = get_kb_item("Services/unknown");

# If no port, or port no longer open, exit.
if (! port) exit(0);
if (! get_port_state(port)) exit(0);

# Did someone else register the service as known? Then exit this instance.
if ( ! service_is_unknown (port: port)) exit(0);

i = 0;
ip = get_host_ip();
argv[i++] = "nmap";
argv[i++] = "-sV";
argv[i++] = "-P0";
argv[i++] = "-p";
argv[i++] = port;
argv[i++] = "-oG";
argv[i++] = "-";
argv[i++] = ip;
res = pread(cmd: "nmap", argv: argv);
# Extract port# and service name from results
extract = eregmatch(string:res, pattern:".*Ports: ([0-9]+)/+open/[^/]*/[^/]*/([^/]*)/.*");

servicesig = extract[2];

# If nmap wasn't sure, it may have added '?' to end of servicesig. Strip it
len = strlen(servicesig);

if(len>0) { 
  lastchar = substr(servicesig, len-1);
  if(lastchar == "?") {
      servicesig = substr(servicesig, 0, len-2);
      guess = TRUE;
  }
}

if(strlen(servicesig)>0) {
    register_service(port: port, proto: servicesig);
    
    message = 'Nmap service detection result for this port: ' + servicesig;

    if(guess) {
      message += '\nThis is a guess. A confident identification of the service was not possible.';
    }  

    log_message(port:port, data:message);
}

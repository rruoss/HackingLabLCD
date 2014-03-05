###############################################################################
# OpenVAS Vulnerability Test
#
# Fetch results of SLAD queries from a remote machine
#
# Primary Authors:
# Dirk Jagdmann
# Michael Wiegand
#
# Changed for GSHB by:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 DN-Systems GmbH
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
################################################################################

include("revisions-lib.inc");
tag_summary = "This script connects to SLAD on a remote host to fetch the SNORT results.
To work properly, this script requires to be provided
with a valid SSH login by means of an SSH key with pass-
phrase if the SSH public key is passphrase-protected, or
a password to log in.";

include ("ssh_func.inc");
include ("slad.inc");

if (description) {
  script_id(96095);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2010-12-01 10:53:45 +0100 (Wed, 01 Dec 2010)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");  
  name = "SLAD snort";
  script_name(name);
  
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  
  summary = "Connects to SLAD to run programs remotely";
  script_summary(summary);
  
  script_category(ACT_GATHER_INFO);
  
  script_copyright("This script is Copyright 2010 DN Systems GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  
  script_dependencies ("find_service.nasl", "ssh_authorization.nasl");
  script_require_ports (22, "Services/ssh");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

function run_slad_snort (sock, slad_exe) {
  global_var snortresult;
  slad_cmd = slad_exe + " -r snort:natcp";
  results = ssh_cmd (socket: sock, cmd: slad_cmd, timeout: 30);
  if (results)  snortresult = results; 
}


sock = ssh_login_or_reuse_connection();
if(!sock) {
  error = get_ssh_error();
  if (!error) error = "No SSH Port or Connection!";
  set_kb_item(name:"GSHB/SLAD/snort", value:"nosock");
  set_kb_item(name:"GSHB/SLAD/snort/log", value:error);    
  exit(0);
}else run_slad_snort (sock: sock, slad_exe: "/opt/slad/bin/sladd");
  


if ("403 plugin already running" >< snortresult || "200 queued" >< snortresult)
{

  slad_exe = '/opt/slad/bin/sladd';
  slad_cmd = slad_exe + ' -s jobs';

  report = ssh_cmd (socket:sock, cmd:slad_cmd, timeout:60);

  bhead = report;
  while (bhead) {
    eol = strstr (bhead, string ("\n"));
    line = substr (bhead, 0, strlen (bhead) - strlen (eol) -1);
    bhead = substr (bhead, strlen (line) + 1);
    parts = split (line, sep: ':', keep: FALSE);
    job = parts[1] + ":" + parts[2] + ":" + parts[3];
    desc = get_slad_description (entry: job);

    if (parts[0] == "R" && parts[1] == "snort" && parts[2] == "snort" && parts[3] == "snort") {
      running += string (desc + "\n");
    } else if (parts[0] == "T" && parts[1] == "snort" && parts[2] == "snort" && parts[3] == "snort") {
      results += string (desc + "\n");
      slad_cmd = slad_exe + ' -s ' + job;
      results += ssh_cmd (socket:sock, cmd:slad_cmd, timeout:60);
      results += string ("\n");
    }
  }
  
  if (results){
    results = ereg_replace(string:results, pattern: '<!--.*-->', replace:'');
  }
  if (!running && !results) results="none";
  else if (!running) set_kb_item(name:"GSHB/SLAD/snort", value:results);
  else if (running) set_kb_item(name:"GSHB/SLAD/snort", value:"running");
}else {
  if (!snortresult) snortresult = "none";
  if ( "/opt/slad/bin/sladd: No such file or directory" >< snortresult || "/opt/slad/bin/sladd: Datei oder Verzeichnis nicht gefunden" >< snortresult ) snortresult = "noslad";
  set_kb_item(name:"GSHB/SLAD/snort", value:snortresult);
}

close (sock);
exit(0);

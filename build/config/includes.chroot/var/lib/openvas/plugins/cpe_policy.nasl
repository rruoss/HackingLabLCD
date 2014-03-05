###############################################################################
# OpenVAS Vulnerability Test
# $Id: cpe_policy.nasl 15 2013-10-27 12:49:54Z jan $
#
# CPE-based Policy Check
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "This NVT is running CPE-based Policy Checks.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;
if (description)
{
 script_id(100353);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-20 12:35:38 +0100 (Fri, 20 Nov 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_name("CPE-based Policy Check");
 script_description(desc);
 script_summary("CPE-based Policy Check");
 script_category(ACT_END);
 script_family("General");

 script_add_preference(name: "Single CPE", value: "cpe:/", type: "entry");
 script_add_preference(name: "CPE List", value: "", type: "file");
 script_add_preference(name: "Severity", type:"radio", value:"High;Medium;Low");
 script_add_preference(name: "Severity upon", type:"radio", value:"present;missing;all missing");

 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("cpe_inventory.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("host_details.inc");

# CPE's registered as host details
cpes = host_details_cpes();

severity      = script_get_preference("Severity");
severity_upon = script_get_preference("Severity upon");
single_cpe    = script_get_preference("Single CPE");

if(!single_cpe || strlen(single_cpe) < 6) {
 cpes_list = script_get_preference_file_content("CPE List");
 if(!cpes_list) {
   cpes_list = script_get_preference("CPE List");
   if(!cpes_list)exit(0);
   sep = ";";
 } else {
   sep = '\n';
 }  
 
 mycpes_split = split(cpes_list, sep: sep, keep:0); 
 mycpes = make_list();

 i = 0;
 foreach mcpe (mycpes_split) {
   if(ereg(pattern:"^cpe:/.*", string: mcpe)) {
      mycpes[i] = mcpe;
      i++;
   }
 }
} 
else
{
    mycpes = make_list(single_cpe);
}

if(!mycpes)exit(0);

running = TRUE;
if(severity_upon == "present") {
  foreach cpe (cpes) {
    foreach mycpe (mycpes) { 
      if(strlen(cpe) >= strlen(mycpe)) {
        if(ereg(pattern: mycpe, string: cpe)) { 
          matches += string(mycpe,"|",cpe,"\n"); 
          reporting = TRUE;
        }
      } 
      else
      {
        if(ereg(pattern: cpe, string: mycpe)) {
          pmatches += string(mycpe,"|",cpe,"\n");
          reporting = TRUE;
        }
      }  
    } 
  }  
} 
else if(severity_upon == "missing") {
  foreach mycpe (mycpes) {
    found = FALSE;
      foreach cpe (cpes) {
        if(!ereg(pattern: "^"+mycpe, string: cpe) && found == FALSE) { 
          found = FALSE;
        } else {
          found = TRUE;
       }
      }
     if(!found) { 
       matches += string(mycpe,"\n");
       reporting = TRUE;
     }
  } 
}  

else if(severity_upon == "all missing") {
  foundany = FALSE;
  foreach mycpe (mycpes) {
    found = FALSE;
    foreach cpe (cpes) {
      if(!ereg(pattern: "^"+mycpe, string: cpe) && found == FALSE) { 
        found = FALSE;
      } else {
        found = TRUE;
        foundany = TRUE;
      }
    }
  }
  if(!foundany) {
    foreach mycpe (mycpes) {
      matches += string(mycpe,"\n");
      reporting = TRUE;
    }
  }
}

if(reporting) {

  if(severity_upon == "present") {
    if(matches) {
      report += string("The following CPEs have been detected on the remote Host\n\nPolicy-CPE|Detected-CPE\n");
      report += matches;
    } 

    if(pmatches) {
      report += string("\nThe following CPEs *may* have been detected on the remote Host\n\nPolicy-CPE|Detected-CPE\n");
      report += pmatches;
    }
  }

  if(severity_upon == "missing") {
    if(matches) {
      report = string("The following CPEs are missing on the remote Host\n\n");
      report += matches;
    }
  }

  if(severity_upon == "all missing") {
    if(matches) {
      report = string("None of the following CPEs are present on the remote Host\n\n");
      report += matches;
    }
  }

 report += string("\nFor further information see http://cpe.mitre.org/\n\nRisk factor : ",severity,"\n"); 
 # port 0 == general/tcp in Client. Maybe port 445 is bettter?
 port = 0;

 if(severity == "Low") {
   security_note(port:port,data:report);
   exit(0);
 } 
 else if(severity == "Medium") {
   security_warning(port:port,data:report);
   exit(0); 
 }
 else if(severity == "High") {
   security_hole(port:port,data:report);
   exit(0);
 }
} else {

  if(running) {

    if(severity_upon == "present") {
      message = string("None of the requested CPEs was found on the remote host\n");
    }  
    else if(severity_upon == "missing") {
      message = string("None of the requested CPEs are missing on the remote host\n"); 
    }  
    else if(severity_upon == "all missing") {
      message = string("At least one of the requested CPEs is present on the remote host\n"); 
    }

    if(message)log_message(port:port,data:message);

  }  
}  

exit(0);



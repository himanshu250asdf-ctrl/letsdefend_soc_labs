### This alert was generated from a real phishing attack.

- Event ID :                  93
- Event Time :                2021-06-13T14:13:28+03:00
- Rule :C146 -                Phishing Mail Detected - Excel 4.0 Macros
- Role :                      Security Analyst
- Alert Type :                Exchange
- Difficulty :                Easy
- MITRE ATT&CK :              T1566
- SMTP Address :              24.213.228.54
- Device Action :             Allowed
- E-mail Subject :            RE: Meeting Notes
- Source Address :            trenton@tritowncomputers.com
- Destination Address :       lars@letsdefend.io

[Alert](./screenshots/alert.png)

### Summary

The investigation began with a warning. The type of warning was a phishing email that had been reported after a user received it together with an attachment. I examined the details of the sender and the attachment in order to find out whether the email was malicious or not, and on the basis of the evidence in question the email was confirmed to be malicious and was found to contain malicious code.

### E-mail
- From:                       trenton@tritowncomputers.com
- To:                         lars@letsdefend.io
- Subject:                    RE: Meeting Notes
- Sender IP:                  24.213.228.54
- Date:                       2021-06-13 16:41:18
- Action:                     Unknown

Hello! Please inspect your docs as one document that you can find through the attachment.
Attachments

### Attachments
11f44531fb088d31307d87b01e8eabff

[Email](./screenshots/email.png)

### Host Information

- Hostname:            LarsPRD
- Domain:              letsdefend.local
- IP Address:          172.16.17.57
- Bit Level:           64-bit
= OS:                  Windows 10
- Primary User:        Lars
- Client/Server:       Server
- Last Login:          2021-06-13 17:17:53

[Host](./screenshots/host.png)

## Investigation 

### SMTP Address

- ISP:	            Charter Communications Inc
- Usage Type:         Fixed Line ISP
- ASN:	            AS11351
- Hostname(s):	    syn-024-213-228-054.biz.spectrum.com
- Domain Name:	    charter.com
- Country:	        United States of America
- City:	            Cobleskill, New York
- Organization:       Charter Communications Inc (CC-3517)
- OrgTechPhone:       +1-866-248-7662 
- OrgTechEmail:       email@charter.com

[SMTP](./screenshots/smtp.png)

### Domain

- Hostname:                      mail.tritowncomputers.com
- IP Address:                    50.6.153.1429(Oracle Corporation (AS31898))		    
- DMARC Record Published:	       No DMARC Record found
- DMARC Policy Not Enabled:      It is recommended to use a quarantine or reject policy.

[Domain](./screenshots/domain.png)

### Finding

A DMARC record was not discovered, which stops the domain from employing DMARC-based authentication and could increase the likelihood of domain spoofing. Yet this result does not mean that the email in question is phishing or malicious.

## Note: This is a personal investigation that has been carried out using the information given in the Let'sDefend lab, with additional OSINT research carried out in order to show the methodology of the investigation. Some of the OSINT findings may not correspond directly to or be linked with the specific indicators involved in the lab's alert and should therefore be regarded as investigative rather than as confirmed evidence of the incident. The aim of this report is to illustrate a practical approach to investigating phishing alerts and to the analysis of alerts and malicious activity.

### Attachments

After the initial sender and domain investigation.I started by searching with the file hash mentioned in the email and the attachment hash was found malicious with a VirusTotal detection score of 37/60. This provided strong evidence that the attachment was malicious.

[Virustotal](./screenshots/virustotal1.png)

**Note:** Don't analyze or run the attached file directly. It's best to change the file extension to prevent accidental clicks and always investigate it in a virtual machine or sandbox.

- File type:            MS Excel Spreadsheet 
- Attachment MD5:       b775cd8be83696ca37b2fe00bcb40574

### Contacted URLs

Scanned	     Detections	    Status	URL

- 2022-02-25	2/ 93            400	http://royalpalm.sparkblue.lk:443/
- 2026-07-08	7/ 92                   https://royalpalm.sparkblue.lk/vCNhYrq3Yg8/dot.html
- 2022-02-25	1/ 93            200	http://nws.visionconsulting.ro:443/
- 2026-07-22	9/ 92            404    https://nws.visionconsulting.ro/N1G1KCXA/dot.html

### Contacted IP addresses

IP	               Detections	Autonomous System	Country
- 192.232.219.67	   1/ 91        31898	             US

- 151.139.128.14	
- 188.209.214.83	
- 188.213.19.81	
- 2.16.42.111	
- 20.190.155.1	
- 20.190.155.130	
- 20.190.155.131	
- 20.190.155.16	
- 20.190.155.2

[virustotal](./screenshots/virustotla3.png)

*Note* Contacted IP addresses but not tag and reported malicious

### File identification
- MD5:                b775cd8be83696ca37b2fe00bcb40574
- SHA-1:              60c8a9fdf2b24f8fb4913d4745a8557df5ff8e07
- SHA-256:            1df68d55968bb9d2db4d0d18155188a03a442850ff543c8595166ac6987df820
- Vhash:              12bd72aca7025d4afc19ecbbc8f16945
- SSDEEP:             6144:Hknl9oBdySAx76F6XeyTVtW/9Ny9ABnl5/PBgxOHjuM9Mn:jl5/WxIji
- TLSH:               T12CE47319E21BA159D321537BFE318385812FBDA2492DBA4B774D7A3EC6F41D0E74A308
- File type:          MS Excel Spreadsheet 
- TrID:               Microsoft Excel sheet (80.2%)   Generic OLE2 / Multistream Compound (19.7%)
- Magika:             XLS
- File size:          648.50 KB (664064 bytes)

### History
- Creation Time:              2015-06-05 18:17:20 UTC
- First Seen In The Wild:     2021-01-12 15:01:01 UTC
- First Submission:           2021-06-13 10:41:28 UTC
- Last Submission:            2026-08-21 01:20:23 UTC
- Last Analysis:              2026-08-19 20:06:06 UTC

[Virustotal](./screenshots/virsutotla2.png)

### Yara Rule

'''rule INDICATOR_DOC_PhishingPatterns 
{
    meta:
        author = "ditekSHen"
        description = "Detects OLE, RTF, PDF and OOXML (decompressed) documents with common phishing strings"
        score = 40
    strings:
        $s1 = "PERFORM THE FOLLOWING STEPS TO PERFORM DECRYPTION" ascii nocase
        $s2 = "Enable Editing" ascii nocase
        $s3 = "Enable Content" ascii nocase
        $s4 = "WHY I CANNOT OPEN THIS DOCUMENT?" ascii nocase
        $s5 = "You are using iOS or Android, please use Desktop PC" ascii nocase
        $s6 = "You are trying to view this document using Online Viewer" ascii nocase
        $s7 = "This document was edited in a different version of" ascii nocase
        $s8 = "document are locked and will not" ascii nocase
        $s9 = "until the \"Enable\" button is pressed" ascii nocase
        $s10 = "This document created in online version of Microsoft Office" ascii nocase
        $s11 = "This document created in previous version of Microsoft Office" ascii nocase
        $s12 = "This document protected by Microsoft Office" ascii nocase
        $s13 = "This document encrypted by" ascii nocase
        $s14 = "document created in earlier version of microsoft office" ascii nocase
    condition:
        (uint16(0) == 0xcfd0 or uint32(0) == 0x74725c7b or uint32(0) == 0x46445025 or uint32(0) == 0x6d783f3c) and 2 of them
}'''


### YARA Analysis

The YARA rule identifies 'OLE RTF PDF or XML' documents based on their file signatures and checks for common phishing-related Office strings such as Enable Editing and Enable Content. The rule requires at least two phishing indicators to trigger.

The rule is heuristic-based, so the match should be treated as supporting evidence of potential phishing activity rather than standalone proof of maliciousness.

*Note*: YARA Analysis by AI

## Client-Side Impact & Attack Chain

1. User received the phishing email.
2. The malicious Excel attachment was delivered to the user's mailbox.
3. The attachment was opened/executed by the user.
4. The excel file call API iroto.dll , iroto.dll1.
5. Network communication May download additional files
6. Execute system commands from dll regsvr32 -s ..\iroto.dll

### Raw Log

[HOST](./screenshots/host_info.png)
[HOST](./screenshots/host_info%20(2).png)

### MITRE ATT&CK Mapping

[MITRE](./screenshots/mitre.png)

### Relationship Graph

[Graph](./screenshots/graph.png)


## Final Assessment

The email had been recognised as a malicious phishing attempt and contained a harmful EXCEL file; the hash of the attachment received a high detection score on VirusTotal and was connected to other network indicators.

The investigation identified the following key indicators:

- Malicious attachment hash
- Conntacted URL : `https://nws.visionconsulting.ro/N1G1KCXA/dot.html'  
                   'https://royalpalm.sparkblue.lk/vCNhYrq3Yg8/dot.html'
- Associated IP addresses
- Suspicious sender information.

The alert is classified as **Malicious Phishing / Malicious Attachment** when viewed in light of the available evidence.

### Recommended Actions

- Put the email in quarantine and remove it from the mailbox.
- Block the URLs, domains, and IP addresses that have been identified as malicious.
- Look for any signs of payload execution or further activity in the review endpoint and the network telemetry.

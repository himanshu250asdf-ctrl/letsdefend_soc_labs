## Alert

- EventID:               45
- Event Time:            2021-01-31T15:48:30+03:00
- Rule:                  SOC114 - Malicious Attachment Detected - Phishing
- Role:                  Security Analyst
- Alert Type:            Exchange
- Difficulty:            Beginner
- MITRE ATT&CK:          T1598.001
- SMTP Address:          49.234.43.39
- Device Action:         Allowed
- E-mail Subject:        Invoice
- Source Address:        accounting@cmail.carleton.ca
- Destination Address:   richard@letsdefend.io

### Summary

This investigation started with an alert. The alert type exchange -phishing email reported after recieved by a user with an attachment. I analyzed the sender information and attachment to determine whether the email was phishing or not. Based on the evidence, the email was confirmed to be malicious and contained a malicious code.


### E-mail

- From:       accounting@cmail.carleton.ca
- To:         richard@letsdefend.io
- Subject:    Invoice
- Sender IP:  49.234.43.39
- Date:       2021-01-31 18:18:30
- Action:     Unknown

Dear customer, Your invoice for the shopping you have done is attached. Regards.


### Attachments
c9ad9506bcccfaa987ff9fc11b91698d

### Host Information

- Hostname:        RichardPRD
- Domain:          letsdefend.local
- IP Address:      172.16.17.45
- Bit Level:       64-bit
- OS:Windows:      10
- PrimarUser:      richard
- Client/Server:   Client

[Host](./screenshots/host%20info.png)

## Investigation 

### SMTP Address

- ISP:         Tencent cloud computing (Beijing) Co., Ltd.
- Usage Type:	 Data Center/Web Hosting/Transit
- ASN:	       AS45090
- Domain Name: tencentcloud.com
- Country:	   China
- City:	       Shanghai, Shanghai

[SMTP](./screenshots/smtp%20address%20check.png)

### Domain

- Mail Server:     cmail-carleton-ca.mail.eo.outlook.com
- IPv4 Address:    52.101.190.0
- IPv6 Address:    2a01:111:f403:c944::
- osting Provider: Microsoft Corporation (AS8075)
- TTL:             60 minutes

[DOMAIN](./screenshots/domain%20check.png)

### Finding 

I performed OSNIT on the domian of source address [accounting@cmail.carleton.ca] and identified cmail-carleton-ca.mail.eo.outlook.com was associated mail server to Microsoft infrastructure and sender SMTP address did not match the domain associated with the identified IP address.

This doesn't establish maliciousness by itself. However the sender SMTP address was also checked on VirusTotal and was flagged by 1 out of 91 security vendors.

- Chong Lua Dao     Malicious
- alphaMountain.ai  Suspicious
- Gridinsoft        Suspicious

[IP](./screenshots/virusttotal_ip.png)

## Note: This is a personal investigation based on the information provided in the Let'sDefend lab. Additional OSINT research was performed to demonstrate the investigation methodology. Some OSINT findings may not directly correspond to or be associated with the specific indicators involved in the lab's alert and these findings should be considered investigative rather than confirmed evidence of the incident. The purpose of this report is to demonstrate a practical methodology for investigating phishing alerts and analyzing alerts and malicious activity.

### Attachments

After the initial sender and domain investigation, I checked whether the attachment contain malicious code. I started by searching with the file hash mentioned in the email and the attachment hash was found malicious with a VirusTotal detection score of 36/62. This provided strong evidence that the attachment was malicious.
 
- File Type:       MS PowerPoint,Excel,Presentation 
- Attachment MD5:  c9ad9506bcccfaa987ff9fc11b91698d

[PPT](./screenshots/virustotal%201.png)

### Contacted URLs

Scanned	          Detections	Status	 URL
- 2026-07-03	      12/ 92        401      http://andaluciabeach.net/image/network.exe
- 2026-08-15	      1/ 92         401	     http://www.andaluciabeach.net/


### Contacted IP addresses

- 194.5.98.8
- 52.111.229.50

[C-IP](./screenshots/virustotal_2.png)

### File identification

- MD5:       c9ad9506bcccfaa987ff9fc11b91698d
- SHA-1:     e788183a2a021f74a21f609e514bb63c4ef2fe49
- SHA-25:    44e65a641fb970031c5efed324676b5018803e0a768608d3e186152102615795
- Vhash:     fe43cc098163d8fb4f1b2b088de0949b
- SSDEEP:    49152:hEK5fuBxYw1iHM+eP4yFIIFd52Mp21N5xb/CVBqCwj7IjLQc1U4l:SK5f6xYSl+VMy8G5ZC6CCIQc1/l
- TLSH:      T145A5334026D14F16D93F52B080DF983653AFCD38FE941E9962063F69B47AA7A33C624D
- File Type: MS PowerPoint
- Magic:     CDFV2 Encrypted
- Magika:    PPT
- TrID:      Microsoft Encrypted Structured Storage Object (73.7%)Encrypted Microsoft Office document(23.9%)  generic OLE2 / Multistream Compound (2.2%)
- File size:  2.12 MB (2218496 bytes)

### History

- First Submission2021-02-01 01:38:50 UTC
- Last Submission2026-08-17 09:43:20 UTC
- Last Analysis2026-07-27 14:28:32 UTC

### Payload URL:

http://andaluciabeach.net/image/network.exe


### Yara Rule

rule autogen_xlsx_Evasive_44e65a64
{
 meta:
  author = "FileScan.IO (http://FileScan.IO/) Engine v1.1.0-e153fde"
  date = "2026-08-17"
  sample = "44e65a641fb970031c5efed324676b5018803e0a768608d3e186152102615795"
  score = 100
  tags = "evasive"
  isWeakRule = true

 strings:
  $magicBytes = {D0 CF 11 E0 A1 B1 1A E1}

  //IOC patterns
  $req0 = "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}N"

  //optional strings
  $opt0 = "EncryptedPackage"
  $opt1 = "EncryptionInfo"
  $opt2 = "Microsoft Enhanced RSA and AES Cryptographic Provider"
  $opt3 = "StrongEncryptionDataSpace"
  $opt4 = "StrongEncryptionTransform"

 condition:
  //require 75% of optional strings
  $magicBytes at 0 and filesize > 1996647 and filesize < 2440345 and all of ($req*) and 3 of ($opt*)
}

### YARA Analysis

The YARA rule identifies an OLE Compound File based on the CDFV2 magic bytes and checks for encryption-related Office strings. The rule also requires a specific GUID and a file size within the defined range.
The rule is tagged as `evasive`, but it is marked as a weak rule (`isWeakRule = true`). Therefore, the YARA match should be treated as supporting evidence rather than standalone proof of maliciousness.

## Client-Side Impact & Attack Chain

### Attack Flow

1. User received the phishing email.
2. The malicious Excel attachment was delivered to the user's mailbox.
3. The attachment was opened/executed by the user.
4. The document initiated malicious activity.
5. The sample contacted the identified payload URL.
6. The executable payload was retrieved.
7. Network communication occurred with the identified IP addresses.

### Raw Log
[HOST_SIDE](./screenshots/raw-log1.png)
[HOST_SIDE_1](./screenshots/rawlog%20(4).png)
[HOST_SIDE_2](./screenshots/Rawlog%20(2).png)
[HOST_SIDE_3](./screenshots/Rawlog%20(3).png)


### MITRE ATT&CK Mapping

[MITRE](./screenshots/mitre.png)


### VirusTotal Relationship Graph

[GRAPH](./screenshots/Screenshot_20260817_155351.png)
[GRAPH_1](./screenshots/Screenshot_20260817_154916.png)


## Final Assessment

The email was determined to be a malicious phishing attempt containing a malicious EXCEL attachment. The attachment hash received a high VirusTotal detection score and was associated with a payload URL and additional network indicators.

The investigation identified the following key indicators:

- Malicious attachment hash
- Payload URL: `http://andaluciabeach.net/image/network.exe`
- Associated IP addresses
- Suspicious sender infrastructure

Based on the available evidence, the alert is classified as **Malicious Phishing / Malicious Attachment**.

### Recommended Actions

- Quarantine and remove the email from the mailbox.
- Block the identified malicious URL, domains, and IP addresses.
- Review endpoint and network telemetry for evidence of payload execution or follow-on activity.
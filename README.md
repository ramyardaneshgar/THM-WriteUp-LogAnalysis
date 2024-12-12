# THM-WriteUp-LogAnalysis
Writeup for TryHackMe Log Analysis Lab - using command line (grep, cut, awk, sort, uniq), CyberChef for decoding and regex-based extraction, Sigma for creating YAML-based detection rules, and YARA for pattern matching to identify structured log anomalies.

Developed by Ramyar Daneshgar 


#### **Question 1**: Extract URLs and identify the unique flag.

**Approach**:
- I used the `cut` command to isolate the URLs in the `apache.log` file, focusing on the 7th field, which contains the URLs:
  ```bash
  cut -d ' ' -f 7 apache.log
  ```
  I chose this method because the `cut` command is quick and effective for extracting specific columns in a structured log file.

- To identify unique URLs and locate the flag, I piped the output through `sort` and `uniq`, ensuring I only got distinct entries:
  ```bash
  cut -d ' ' -f 7 apache.log | sort | uniq
  ```
  This is a useful method for reducing redundant entries and simplifying the data before examining it further. Among the unique entries, I found the flag: `c701d43cc5a3acb9b5b04db7f1be94f6`.

**Reasoning**:
The `cut` command efficiently extracts the relevant data (URLs), and using `sort` and `uniq` allows me to focus on distinct values, which is crucial for identifying important events, such as the flag.

---

#### **Question 2**: Count total HTTP 200 responses.

**Approach**:
- To count HTTP 200 responses in the log, I used `grep` to search for " 200 " in the `apache.log` file, which represents successful HTTP requests:
  ```bash
  grep ' 200 ' apache.log
  ```
- To count how many times this response code appeared, I piped the output to `wc -l`, which counts the number of lines:
  ```bash
  grep ' 200 ' apache.log | wc -l
  ```
  This provided the total number of HTTP 200 responses: `52`.

**Reasoning**:
By filtering for HTTP status code 200, I focused only on successful requests, which is useful for understanding the overall traffic and identifying any issues with failed requests.

---

#### **Question 3**: Identify the IP address generating the most traffic.

**Approach**:
- To identify the IP address with the most traffic, I extracted the IP addresses from the `apache.log` file using the `cut` command:
  ```bash
  cut -d ' ' -f 1 apache.log
  ```
- I then sorted the IP addresses, counted the occurrences using `uniq -c`, and sorted them in reverse order to find the IP with the highest traffic:
  ```bash
  cut -d ' ' -f 1 apache.log | sort | uniq -c | sort -nr
  ```
  The IP address with the highest traffic was `145.76.33.201`.

**Reasoning**:
Sorting and counting IP addresses help identify sources of high traffic, which can indicate both legitimate usage patterns and potential malicious activity, such as DDoS attacks.

---

#### **Question 4**: Locate the timestamp of the entry where `110.122.65.76` accessed `/login.php`.

**Approach**:
- To find the relevant entry, I used `grep` to filter for the specific IP address and the `/login.php` endpoint:
  ```bash
  grep '110.122.65.76' apache.log | grep '/login.php'
  ```
  This search returned the full log entry containing the timestamp: `31/Jul/2023:12:34:40 +0000`.

**Reasoning**:
By filtering for both the IP and endpoint, I could pinpoint the exact log entry that matched my query. This method is efficient for investigating suspicious activities linked to specific users or actions.

---

### Task 8: Log Analysis Using CyberChef

#### **Question 1**: Extract all IP addresses from `access.log`.

**Approach**:
- I uploaded the `access.log` file to CyberChef and applied the **Regex** operation with the pattern:
  ```regex
  \b([0-9]{1,3}\.){3}[0-9]{1,3}\b
  ```
  This regex pattern identifies all IPv4 addresses in the log. I chose this pattern because it captures standard IPv4 address structures, ensuring a broad range of valid IPs are matched.

- The pattern returned the IP starting with `212`, which was `212.14.17.145`.

**Reasoning**:
CyberChef’s Regex operation is powerful for extracting data from unstructured logs, and using the right regex pattern ensures accuracy and efficiency when searching for specific data types, like IP addresses.

---

#### **Question 2**: Decode a base64-encoded request.

**Approach**:
- I identified the base64-encoded string within the `access.log` file by recognizing typical base64 patterns.
- I used CyberChef’s **From Base64** operation to decode the string, revealing the flag: `THM{CYBERCHEF_WIZARD}`.

**Reasoning**:
Base64 encoding is commonly used to obscure data. Decoding it in CyberChef allowed me to extract the hidden flag, demonstrating how encoding techniques can be easily reversed with the right tools.

---

#### **Question 3**: Decode `encodedflag.txt` and extract the MAC address.

**Approach**:
- I uploaded `encodedflag.txt` to CyberChef and applied the appropriate decoding operation (e.g., Base64 or Hex decoding).
- After decoding, I used the **Regex** operation with the pattern:
  ```regex
  ([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}
  ```
  This pattern extracts the MAC address: `08-2E-9A-4B-7F-61`.

**Reasoning**:
Regex is ideal for extracting structured data such as MAC addresses, and CyberChef's automated operations make it easy to decode and then search for specific patterns, streamlining the analysis process.

---

### Task 9: Detection Using Sigma and YARA

#### **Question 1**: Define Sigma rule syntax.

**Approach**:
Sigma rules are defined using `YAML`, which is a human-readable data format. I reviewed the example rules provided in the task to confirm this.

---

#### **Question 2**: Identify Sigma rule structure.

**Approach**:
The `title` keyword is used to specify the name or purpose of the Sigma rule. I confirmed this by reviewing the sample rules.

---

#### **Question 3**: Name YARA rule components.

**Approach**:
In YARA, the keyword `rule` is used to define the rule itself. This is consistent across all YARA rules, which are designed for pattern matching.

---

### Lessons Learned

1. **Command-line tools**: I learned how to efficiently use tools like `grep`, `cut`, `sort`, and `uniq` for quick log parsing and extraction, which is crucial in real-time analysis.
2. **Regex**: The importance of regex in extracting structured data (e.g., IPs, MAC addresses) from logs was emphasized, particularly using CyberChef for decoding and pattern extraction.
3. **CyberChef**: CyberChef proved invaluable for encoding/decoding tasks and applying regex operations, highlighting its role in simplifying complex log analysis tasks.
4. **Sigma and YARA**: I gained an understanding of using Sigma for structured threat detection and YARA for pattern matching in logs, which are essential for automating threat detection.


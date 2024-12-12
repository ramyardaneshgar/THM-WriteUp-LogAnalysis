# THM-WriteUp-LogAnalysis

## TryHackMe Log Analysis Lab  
### Developed by Ramyar Daneshgar  

This writeup details my technical approach and reasoning for solving challenges in the TryHackMe "Log Analysis" lab. The lab required using command-line tools (`grep`, `cut`, `awk`, `sort`, `uniq`), **CyberChef** for decoding and regex-based extraction, **Sigma** for creating YAML-based detection rules, and **YARA** for pattern matching to identify structured log anomalies. Below, I break down each solution, including the logic and context behind every step.

---

### **Task 6: Command-Line Log Analysis**

#### **Question 1**: Extract URLs and identify the unique flag.

**Approach**:
1. I analyzed the `apache.log` file to isolate the field containing URLs. Using the `cut` command with the space character as the delimiter (`-d ' '`), I extracted the 7th field:
   ```bash
   cut -d ' ' -f 7 apache.log
   ```
2. To identify unique URLs, I piped the results through `sort` and `uniq`. Sorting ensures adjacent duplicates are grouped, allowing `uniq` to filter distinct entries:
   ```bash
   cut -d ' ' -f 7 apache.log | sort | uniq
   ```
3. Examining the output revealed the flag: `c701d43cc5a3acb9b5b04db7f1be94f6`.

**Reasoning**:
This approach leverages `cut` for efficient field extraction and `sort | uniq` to simplify and focus on unique entries. The method reduces noise and is especially effective for large datasets where patterns or specific entries need to be identified.

---

#### **Question 2**: Count total HTTP 200 responses.

**Approach**:
1. Using `grep`, I filtered the log for lines containing the HTTP 200 status code, which indicates successful requests:
   ```bash
   grep ' 200 ' apache.log
   ```
2. I piped the output to `wc -l` to count the number of matching lines:
   ```bash
   grep ' 200 ' apache.log | wc -l
   ```
3. The command returned a total of `52` HTTP 200 responses.

**Reasoning**:
Filtering specific HTTP status codes is a common way to assess system performance and detect anomalies in traffic patterns. The combination of `grep` and `wc` provides both precision and efficiency.

---

#### **Question 3**: Identify the IP address generating the most traffic.

**Approach**:
1. To focus on source IPs, I used `cut` to extract the first field (IP addresses):
   ```bash
   cut -d ' ' -f 1 apache.log
   ```
2. To analyze traffic volume per IP, I sorted the results numerically and applied `uniq -c` to count occurrences. Finally, I sorted the counts in reverse order:
   ```bash
   cut -d ' ' -f 1 apache.log | sort | uniq -c | sort -nr
   ```
3. The IP generating the most traffic was `145.76.33.201`.

**Reasoning**:
High-frequency IPs could indicate legitimate users or potential malicious activity, such as a brute-force or DDoS attack. Sorting and counting provided a clear breakdown of traffic sources.

---

#### **Question 4**: Locate the timestamp where `110.122.65.76` accessed `/login.php`.

**Approach**:
1. I used `grep` to filter log entries for the IP address `110.122.65.76` and the `/login.php` endpoint:
   ```bash
   grep '110.122.65.76' apache.log | grep '/login.php'
   ```
2. The resulting log entry revealed the timestamp: `31/Jul/2023:12:34:40 +0000`.

**Reasoning**:
Combining multiple `grep` commands allowed me to narrow down results quickly, making it efficient to investigate specific user actions or events.

---

### **Task 8: Log Analysis Using CyberChef**

#### **Question 1**: Extract all IP addresses from `access.log`.

**Approach**:
1. I uploaded the `access.log` file to CyberChef and applied the **Regex** operation with the pattern:
   ```regex
   \b([0-9]{1,3}\.){3}[0-9]{1,3}\b
   ```
   This pattern matches standard IPv4 addresses. It ensures the extraction of valid IP formats, avoiding false matches.

2. CyberChef processed the log and displayed a list of extracted IPs. Among them, I identified the IP starting with `212`: `212.14.17.145`.

**Reasoning**:
Using regex in CyberChef simplifies parsing unstructured log data, and its intuitive interface allows for rapid iteration and validation of extraction patterns.

---

#### **Question 2**: Decode a base64-encoded request.

**Approach**:
1. I located the base64-encoded request in the log by identifying typical base64 patterns (alphanumeric characters with `=` padding).
2. Using CyberChef’s **From Base64** operation, I decoded the string to reveal the flag: `THM{CYBERCHEF_WIZARD}`.

**Reasoning**:
CyberChef excels at handling encoding and decoding operations, making it ideal for identifying hidden data in logs. Base64 is a common encoding method, often used to obfuscate sensitive information.

---

#### **Question 3**: Decode `encodedflag.txt` and extract the MAC address.

**Approach**:
1. I uploaded `encodedflag.txt` to CyberChef and applied decoding operations (e.g., Base64 or Hex) to reveal the contents.
2. I used the **Regex** operation with the following pattern to extract MAC addresses:
   ```regex
   ([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}
   ```
   This matched MAC addresses in standard formats. The extracted value was `08-2E-9A-4B-7F-61`.

**Reasoning**:
Regex in CyberChef provides precise extraction of structured data like MAC addresses. Automating the decoding and matching process ensures accuracy while minimizing manual errors.

---

### **Task 9: Detection Using Sigma and YARA**

#### **Question 1**: Define Sigma rule syntax.

**Approach**:
Sigma uses the human-readable `YAML` format for defining detection rules. I reviewed provided examples and confirmed this syntax.

---

#### **Question 2**: Identify Sigma rule structure.

**Approach**:
The `title` keyword in Sigma defines the rule’s purpose, helping categorize and document detection rules effectively.

---

#### **Question 3**: Name YARA rule components.

**Approach**:
In YARA, the `rule` keyword names each detection pattern. This keyword serves as the foundation for YARA’s pattern-matching logic.

---

### **Key Lessons Learned**

1. **Command-Line**: Leveraging tools like `grep`, `cut`, `sort`, and `uniq` enhances efficiency in parsing large log files and pinpointing key insights.
2. **CyberChef**: This versatile tool simplifies complex operations like decoding, regex-based extraction, and data parsing, making it indispensable for log analysis.
3. **Regex**: Developing and applying effective regex patterns is critical for extracting structured data, such as IP addresses and MAC addresses, from unstructured logs.
4. **Automation with Sigma and YARA**: These tools streamline detection through standardized rule formats, providing scalable solutions for identifying threats in logs.

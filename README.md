

## Repository
| File | Description |
| --- | --- |
| /env | Virtual environment |
| data_query.ipynb | Collecting data from Vulnerability API |
| nvd_cve.db | Database, which contains tables cve and cve_product |
| app.py | Flask API to answer business questions |
| test_request.ipynb | Requesting data from our API |


## ETL design

### Extract data from Vulnerability API:
We query data via Jupyter Notebook because:
- It's more hands-on.
- It helps to play around with the data more easily.
- We only collect historical data, so there's no need to create an active data collection pipeline.

The extraction process is set up incrementally by querying 2000 CVEs per request, as this is the max limit from the NVD side. We will exclude all rejected CVEs because they don't contain any meaningful information for us (of course, in the future, it could make sense to still include them and understand what type of CVEs aren’t analyzed, e.g.). We also ensure that CVE vulnerability status is either [ANALYSED or MODIFIED](https://nvd.nist.gov/vuln/vulnerability-status#divNvdStatus), which gives confidence that we are excluding noise from a business perspective. We have predefined restrictions from the business side as well. Thus, we exclude such CVEs which have been added or modified after 2024-05.

Example of query URL (10 responses): 
```
https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=10&startIndex=0&noRejected
```

To extract product information, we will be using additionaly [pyhton CVE package](https://pypi.org/project/cve-py/) to get product basic info (platform and product) with ease.

Found later [pyhton CVSS package](https://pypi.org/project/cvss/), which would make the code more readable.

### Transform:
We will transform the input (JSON) to the CVE level and later to a more granular level (CVE-product level). By knowing the business needs, we can restrict the data scope (please read the data model description to see the final output). A CVE needs to have at least either CVSS version 2 or version 3 metrics (if version 3 exists, then taking this information as truth, else version 2).

### Load:
Data is stored in the database **nve_cad** into tables **cve** and **cve_product** respectively.

### Performance and Scalability:
Currently, the process has only one worker, which is considered optimal for this case, but in the future, it’s recommended to build a dynamic function that could be applied for every API and allows increasing the worker amount and finding the optimal size, where the tradeoff should be defined via time vs # of data points.

### Error Handling and Monitoring:
The biggest risk factor when querying the data is related to the network connection and API response. This is mitigated by time delay and retry (10 times). If the process still fails after that, then those runs will be highlighted separately, and a manual rerun will be needed for them later.

## [Database desing](https://dbdiagram.io/d/66980a498b4bb5230e9ebd85)
The current database is built/structured to answer specific business questions only. It's recommended to understand if the company will be interested in a wider scope, which helps to be more proactive. This way, DE will not be a blocker for end users (PM/DS/DA) and DE can spend resources on more critical tasks (less time will be spent on adding additional variables and doing backfills).

$${\color{red}\text{PS! Next chapters assumes that the reader is familiar with pyhton basics.}}$$

## Setting up the database
Here are the step-by-step instructions on how to set up the database **nve_cad** (if it doesn't exist or if there is a need to recreate it):
- Make sure you have Jupyter Notebook installed.
- Open the terminal.
- Navigate to the repository.
- Type **jupyter notebook**.
- Open the file **data_query.ipynb** and "run all".
  - If you encounter any problems when installing packages, then just add new line(s) above with "pip install <package_name>".
  - You will see logs:
    - Incremental (start and end index)
    - Duration
    - Indication of when we have breached the threshold (2024-05)
    - Total time
    - Failed increments
 
## Setting up the REST API
- Open the terminal.
- Make sure you have [virtual enviroment](https://pypi.org/project/virtualenv/) package installed.
- Navigate to the repository.
- Type **source env/bin/activate**. You should be seeing line **(env)** command line in the terminal.
- Type **pyhton3 app.py** 
- From terminal logs, determine server IP (look for **Running on http://...**).
  - When running it locally, then we can use **http://127.0.0.1:5000**
- When you open the server in a web brouser, then you should be seeing **Final results**
- Please read API documentation to understand endpoints

## API documentation

Below, you will find a list of all unique endpoints along with their possible parameters. Toggle the endpoint to see a sample result.

All possible endpoints
``` /help ```
<details>
  
```javascript
{
  "code": 200,
  "data": [
    {
      "/": "API base URL"
    },
    {
      "/help": "Print all defined routes and their endpoint docstrings."
    },
    {
      "/severity/dist": "Base severity distribution."
    },
    {
      "/severity/year": "Base severity change over time"
    },
    {
      "/worst_products_platforms/\u003Cstring:prod_or_plat\u003E": "Get top 10 worst products/platforms. Variable prod_or_plat = [product,platform]"
    },
    {
      "/top_vul/\u003Cint:cvss_ver\u003E/\u003Cstring:score\u003E": "Get top 10 vulnerabilities based on the score and cvss version. cvss_ver = [2,3] & score = [impact_score,exploitability_score]"
    },
    {
      "/cve_or_prod/\u003Cstring:cve_or_prod\u003E/\u003Cstring:id\u003E": "Possibility to query information about either CSV (https://nvd.nist.gov/vuln/search) or product ID (https://nvd.nist.gov/products/cpe/search)"
    }
  ]
}
```
</details>

Severity distribution
``` /severity/dist ```
<details>
<summary></summary>
  
```javascript
{
  "severity_distribution": [
    {
      "CRITICAL": 7216
    },
    {
      "LOW": 14657
    },
    {
      "HIGH": 65123
    },
    {
      "MEDIUM": 93112
    }
  ]
}
```
</details>

Extra: How severity has changed over time. Defined avg severity via LOW = 0, MEDIUM = 1, HIGH = 2, CRITICAL = 3
``` /severity/year ```
<details>
<summary></summary>
  
```javascript
{
  "severity_distribution": [
    {
      "avg_base_severity": 2,
      "n_cve": 2,
      "year": "1988"
    },
    {
      "avg_base_severity": 1.67,
      "n_cve": 3,
      "year": "1989"
    },
    {
      "avg_base_severity": 1.64,
      "n_cve": 11,
      "year": "1990"
    },
    {
      "avg_base_severity": 1.73,
      "n_cve": 15,
      "year": "1991"
    },
    {
      "avg_base_severity": 1.85,
      "n_cve": 13,
      "year": "1992"
    },
    {
      "avg_base_severity": 1.46,
      "n_cve": 13,
      "year": "1993"
    },
    {
      "avg_base_severity": 1.52,
      "n_cve": 25,
      "year": "1994"
    },
    {
      "avg_base_severity": 1.68,
      "n_cve": 25,
      "year": "1995"
    },
    {
      "avg_base_severity": 1.47,
      "n_cve": 74,
      "year": "1996"
    },
    {
      "avg_base_severity": 1.49,
      "n_cve": 252,
      "year": "1997"
    },
    {
      "avg_base_severity": 1.46,
      "n_cve": 246,
      "year": "1998"
    },
    {
      "avg_base_severity": 1.34,
      "n_cve": 894,
      "year": "1999"
    },
    {
      "avg_base_severity": 1.35,
      "n_cve": 1018,
      "year": "2000"
    },
    {
      "avg_base_severity": 1.35,
      "n_cve": 1673,
      "year": "2001"
    },
    {
      "avg_base_severity": 1.39,
      "n_cve": 2149,
      "year": "2002"
    },
    {
      "avg_base_severity": 1.38,
      "n_cve": 1523,
      "year": "2003"
    },
    {
      "avg_base_severity": 1.31,
      "n_cve": 2440,
      "year": "2004"
    },
    {
      "avg_base_severity": 1.32,
      "n_cve": 4896,
      "year": "2005"
    },
    {
      "avg_base_severity": 1.33,
      "n_cve": 6485,
      "year": "2006"
    },
    {
      "avg_base_severity": 1.45,
      "n_cve": 6389,
      "year": "2007"
    },
    {
      "avg_base_severity": 1.47,
      "n_cve": 5604,
      "year": "2008"
    },
    {
      "avg_base_severity": 1.44,
      "n_cve": 5701,
      "year": "2009"
    },
    {
      "avg_base_severity": 1.39,
      "n_cve": 4591,
      "year": "2010"
    },
    {
      "avg_base_severity": 1.36,
      "n_cve": 4135,
      "year": "2011"
    },
    {
      "avg_base_severity": 1.23,
      "n_cve": 5211,
      "year": "2012"
    },
    {
      "avg_base_severity": 1.23,
      "n_cve": 5149,
      "year": "2013"
    },
    {
      "avg_base_severity": 1.16,
      "n_cve": 7891,
      "year": "2014"
    },
    {
      "avg_base_severity": 1.28,
      "n_cve": 6453,
      "year": "2015"
    },
    {
      "avg_base_severity": 1.64,
      "n_cve": 6407,
      "year": "2016"
    },
    {
      "avg_base_severity": 1.67,
      "n_cve": 14499,
      "year": "2017"
    },
    {
      "avg_base_severity": 1.72,
      "n_cve": 16329,
      "year": "2018"
    },
    {
      "avg_base_severity": 1.44,
      "n_cve": 17055,
      "year": "2019"
    },
    {
      "avg_base_severity": 1.15,
      "n_cve": 18166,
      "year": "2020"
    },
    {
      "avg_base_severity": 1.08,
      "n_cve": 19897,
      "year": "2021"
    },
    {
      "avg_base_severity": 1.19,
      "n_cve": 13683,
      "year": "2022"
    },
    {
      "avg_base_severity": 1.61,
      "n_cve": 1144,
      "year": "2023"
    },
    {
      "avg_base_severity": 1.79,
      "n_cve": 47,
      "year": "2024"
    }
  ]
}
```
</details>


Worst products or platforms defined via count. Includes only vulnerable and not negated products. 
``` /worst_products_platforms/<prod_or_plat> ```

**prod_or_plat**
- product
- platform
<details>
<summary></summary>
  
```javascript
{
  "result": [
    {
      "n_cve": 82674,
      "product": "linux_kernel",
      "vendor": "linux"
    },
    {
      "n_cve": 46952,
      "product": "ios",
      "vendor": "cisco"
    },
    {
      "n_cve": 30584,
      "product": "junos",
      "vendor": "juniper"
    },
    {
      "n_cve": 28142,
      "product": "chrome",
      "vendor": "google"
    },
    {
      "n_cve": 21535,
      "product": "firefox",
      "vendor": "mozilla"
    },
    {
      "n_cve": 20084,
      "product": "opera_browser",
      "vendor": "opera"
    },
    {
      "n_cve": 17418,
      "product": "windows_10",
      "vendor": "microsoft"
    },
    {
      "n_cve": 15863,
      "product": "safari",
      "vendor": "apple"
    },
    {
      "n_cve": 15659,
      "product": "android",
      "vendor": "google"
    },
    {
      "n_cve": 15592,
      "product": "mac_os_x",
      "vendor": "apple"
    }
  ],
  "type": "product"
}
```
</details>

Top 10 vulnerabilities that have the highest impact or highest exploitability scores depending on the CVSS ver (2 or 3). Highest is defined via sum.
``` /top_vul/<cvss_ver>/<score> ```

**cvss_ver**
- 2
- 3
  
**score**
- impact_score
- exploitability_score

Example URL ```http://127.0.0.1:5000/top_vul/3/impact_score```
<details>
<summary></summary>

```jsonscript
{
  "cvss_ver": 3,
  "result": [
    {
      "avg_score": 5.9,
      "n_cve": 6004,
      "sum_score": 35423.6,
      "vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    {
      "avg_score": 5.9,
      "n_cve": 3392,
      "sum_score": 20012.8,
      "vector_string": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
    },
    {
      "avg_score": 5.9,
      "n_cve": 3111,
      "sum_score": 18354.9,
      "vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
    },
    {
      "avg_score": 5.9,
      "n_cve": 2263,
      "sum_score": 13351.7,
      "vector_string": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    },
    {
      "avg_score": 5.9,
      "n_cve": 1707,
      "sum_score": 10071.3,
      "vector_string": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    },
    {
      "avg_score": 2.7,
      "n_cve": 3667,
      "sum_score": 9900.9,
      "vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    },
    {
      "avg_score": 3.6,
      "n_cve": 2202,
      "sum_score": 7927.2,
      "vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    },
    {
      "avg_score": 3.6,
      "n_cve": 1862,
      "sum_score": 6703.2,
      "vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    },
    {
      "avg_score": 2.7,
      "n_cve": 1812,
      "sum_score": 4892.4,
      "vector_string": "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
    },
    {
      "avg_score": 5.9,
      "n_cve": 695,
      "sum_score": 4100.5,
      "vector_string": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
    }
  ],
  "score_type": "impact_score"
}
```
</details>

Possible to extract individual information on CVE or product level.
``` /cve_or_prod/<cve_or_prod>/<id> ```

**cve_or_prod**
- cve
- product

**id**
- CSV ID (https://nvd.nist.gov/vuln/search)
- product ID (https://nvd.nist.gov/products/cpe/search)

Example URL: ```http://127.0.0.1:5000/cve_or_prod/cve/CVE-2000-0388```
<details>
<summary></summary>

```jsonscript
{
  "result": [
    {
      "base_score": 7.5,
      "base_severity": "HIGH",
      "cve": "CVE-2000-0388",
      "cvss_ver": 2,
      "exploitability_score": 10,
      "id": 7,
      "impact_score": 6.4,
      "last_ingested": "2024-07-21 19:07:24.752358",
      "last_modified": "2008-09-10T19:04:33.930",
      "published": "1990-05-09T04:00:00.000",
      "vector_string_v2": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
      "vector_string_v3": null,
      "vuln_status": "ANALYZED"
    }
  ],
  "type": "cve"
}
```
</details>
  














# cve2022-26134exp

0x01 漏洞描述

近日，Atlassian官方发布了Confluence Server和Data Center OGNL 注入漏洞（CVE-2022-26134）的安全公告。该漏洞的CVSS评分为10分，目前漏洞细节与PoC已被公开披露，且被检测到存在在野利用。
Atlassian Confluence是Atlassian公司出品的专业wiki程序。攻击者可利用漏洞在未经身份验证的情况下，远程构造OGNL表达式进行注入，在Confluence Server或Data Center上执行任意代码。

结合Crowsec Edtech的exp增加了一个反弹shell的功能和命令行指定参数的方式


执行


<img width="863" alt="image" src="https://user-images.githubusercontent.com/42299567/172033656-16591d79-a46b-4a2c-8472-25a1a0fd8832.png">



示例：


<img width="863" alt="image" src="https://user-images.githubusercontent.com/42299567/172033727-2993f465-39d8-49cb-bc48-2c2ca3ddd5bc.png">


<img width="1855" alt="image" src="https://user-images.githubusercontent.com/42299567/172033766-fff63d00-67ae-491b-8613-f8032cb2e27f.png">


## 디지털 포렌식

<table style="table-layout:fixed;width:100%">
  <colgroup>
    <col style="width:20%">
    <col style="width:30%">
    <col style="width:50%">
  </colgroup>
  <thead>
    <tr>
      <th>도구(링크 추가)</th>
      <th>역할</th>
      <th>입력</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><a href="https://github.com/mgreen27/mcp-velociraptor">Velociraptor MCP</a></td>
      <td>디스크 아티팩트 / 원격 증거 수집·배포</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>.e01</code>, <code>.VMDK</code>, <code>.VHDX</code>, <code>raw(.dd, flat)</code>
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/ThreatFlux/YaraFlux">YARA MCP</a></td>
      <td>파일·시그니처 분석 / 룰 기반 악성코드 매칭</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>string(base64, plain text)</code>
      </td>
    </tr>
  </tbody>
</table>


## 코드 보안

<table style="table-layout:fixed;width:100%">
  <colgroup>
    <col style="width:20%">
    <col style="width:30%">
    <col style="width:50%">
  </colgroup>
  <thead>
    <tr>
      <th>도구(링크 추가)</th>
      <th>역할</th>
      <th>입력</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><a href="https://github.com/semgrep/mcp">Semgrep MCP</a></td>
      <td>코드 보안 분석 / 웹셸·드로퍼 정적 분석</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>C#(.cs)</code>, <code>Go(.go)</code>, <code>Java(.java)</code>, <code>JavaScript(.js)</code>, 
        <code>TypeScript(.ts,.tsx)</code>, <code>C/C++(.c,.h,.cc,.cpp,.cxx,.hh,.hpp,.hxx)</code>, 
        <code>JSX(.jsx)</code>, <code>Ruby(.rb)</code>, <code>Scala(.scala)</code>, <code>Swift(.swift)</code>, 
        <code>Rust(.rs)</code>, <code>PHP(.php,.phtml)</code>, <code>Kotlin(.kt,.kts)</code>, <code>Python(.py)</code>, 
        <code>Terraform(.tf)</code>, <code>JSON(.json)</code>, <code>YAML(.yaml,.yml)</code>, 
        <code>Elixir(.ex,.exs)</code>, <code>Apex(.cls)</code>, <code>Dart(.dart)</code>
      </td>
    </tr>
  </tbody>
</table>


## 리버스 엔지니어링

<table style="table-layout:fixed;width:100%">
  <colgroup>
    <col style="width:20%">
    <col style="width:30%">
    <col style="width:50%">
  </colgroup>
  <thead>
    <tr>
      <th>도구(링크 추가)</th>
      <th>역할</th>
      <th>입력</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><a href="https://github.com/LaurieWired/GhidraMCP">Ghidra MCP</a></td>
      <td>정적 분석·리버스 엔지니어링</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>COFF</code>, <code>DWARF</code>, <code>ELF</code>, <code>Golang</code>, <code>LX</code>, <code>Mach-O</code>, <code>MZ</code>, <code>NE</code>, <code>Objective-C/objc2</code>, <code>OMF</code>, <code>PDB</code>, <code>PE</code>, <code>PEF</code>, <code>Swift</code>, <code>UBI</code>, <code>UNIX a.out</code>, <code>XCOFF</code>
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/fosdickio/binary_ninja_mcp">Binary Ninja MCP</a></td>
      <td>악성코드 정적 분석·리버스</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>TEXT(JSON)</code> 함수명/주소/새 이름 등 — 로드된 바이너리에 동작
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/mrexodia/ida-pro-mcp">IDA Pro MCP</a></td>
      <td>악성코드 정적 분석·리버스</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>TEXT(JSON)</code> 함수명, 주소, 심볼 등
      </td>
    </tr>
  </tbody>
</table>


## 위협 인텔리전스

<table style="table-layout:fixed;width:100%">
  <colgroup>
    <col style="width:20%">
    <col style="width:30%">
    <col style="width:50%">
  </colgroup>
  <thead>
    <tr>
      <th>도구(링크 추가)</th>
      <th>역할</th>
      <th>입력</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><a href="https://github.com/burtthecoder/mcp-virustotal">VirusTotal MCP</a></td>
      <td>악성 여부 판별(파일/해시/IP/도메인)</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>url</code>, <code>hash</code>, <code>ip</code>, <code>domain</code>, <code>relationships</code>
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/alex-llm/attAck-mcp-server">attAck MCP</a></td>
      <td>공격 행위 MITRE ATT&amp;CK 매핑</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>technique_id</code> / <code>technique_name</code> (<code>string</code>)
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/cjinzy/stealthmole-mcp-server">StealthMole MCP</a></td>
      <td>다크웹/OSINT 위협 인텔 수집 보강</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>indicator</code>, <code>text</code>, <code>target</code>, <code>limit</code>, <code>orderType</code>, <code>order</code> (<code>TEXT JSON</code>)
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/bornpresident/MISP-MCP-SERVER">MISP MCP</a></td>
      <td>IoC 위협 인텔 조회·교차 검증</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>ioc_value</code>, <code>ioc_type</code>, <code>event_info</code>, <code>md5</code>, <code>sha1</code>, <code>sha256</code>, <code>filename</code>, <code>ip-src</code>, <code>ip-dst</code>, <code>domain</code>, <code>url</code>, <code>email</code> (<code>TEXT JSON/IoC 타입</code>)
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/AshfaaqF/mcp-priam-alienvault">Priam AlienVault MCP</a></td>
      <td>AlienVault OTX 기반 IoC 교차검증</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>ip_address</code>, <code>ipv6_address</code>, <code>domain</code>, <code>hostname</code>, <code>url</code>, <code>file_hash(md5|sha1|sha256)</code>, <code>cve_id</code>, <code>query</code> (<code>TEXT JSON</code>)
      </td>
    </tr>
  </tbody>
</table>


## 취약점·평가

<table style="table-layout:fixed;width:100%">
  <colgroup>
    <col style="width:20%">
    <col style="width:30%">
    <col style="width:50%">
  </colgroup>
  <thead>
    <tr>
      <th>도구(링크 추가)</th>
      <th>역할</th>
      <th>입력</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><a href="">EPSS MCP</a></td>
      <td>취약점 심각도·악용 가능성 평가</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        HTTP GET 경로: <code>/cve/&lt;CVE-ID&gt;</code> (<code>TEXT</code>: CVE ID 문자열)
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/roadwy/cve-search_mcp">CVE-Search MCP</a></td>
      <td>취약점 검색·평가</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>cve_id</code>, <code>vendor</code>, <code>product</code>, <code>search</code> (<code>TEXT JSON</code>)
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/StacklokLabs/osv-mcp">OSV MCP</a></td>
      <td>취약점 검색·평가</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>commit</code>, <code>version</code>, <code>package_name</code>, <code>ecosystem</code>, <code>purl</code> (<code>TEXT JSON</code>)
      </td>
    </tr>
  </tbody>
</table>


## 네트워크 기반 보안

<table style="table-layout:fixed;width:100%">
  <colgroup>
    <col style="width:20%">
    <col style="width:30%">
    <col style="width:50%">
  </colgroup>
  <thead>
    <tr>
      <th>도구(링크 추가)</th>
      <th>역할</th>
      <th>입력</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><a href="https://github.com/elastic/mcp-server-elasticsearch">Elasticsearch MCP</a></td>
      <td>로그·SIEM 분석 / 수집·검색·위협 헌팅</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>index</code>, <code>query</code>, <code>size</code> 등 (<code>TEXT JSON</code>)
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/capelabs/opensearch-mcp-server">OpenSearch MCP</a></td>
      <td>로그·SIEM 분석 / 수집·검색·위협 헌팅</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>index</code>, <code>query</code>, <code>size</code> 등 (<code>TEXT JSON</code>)
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/Gabbo01/Zeek-MCP">Zeek MCP</a></td>
      <td>네트워크 침해 탐지 / 세션 기반 분석</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>.pcap</code>
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/Medinios/SuricataMCP">Suricata MCP</a></td>
      <td>네트워크 트래픽·IDS 룰 기반 탐지</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>.pcap</code>
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/Hexastrike/EventWhisper">EventWhisper (Hexastrike)</a></td>
      <td>Windows 이벤트 로그 기반 침해 흔적 분석</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>.evtx</code>
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/gensecaihq/Wazuh-MCP-Server">Wazuh MCP</a></td>
      <td>로그·SIEM 분석 / 수집·검색·위협 헌팅</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>query</code>, <code>index</code>, <code>filters</code> 등 (<code>TEXT JSON</code>)
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/BurtTheCoder/mcp-shodan">Shodan MCP Server</a></td>
      <td>공격자 IP/자산 노출 상태, 오픈 포트 확인</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>ip</code>
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/alxspiker/Windows-Command-Line-MCP-Server">Windows Command Line MCP</a></td>
      <td>Windows Command Line 실행</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>TEXT</code>(command/PowerShell 스크립트/명령)
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/AIM-Intelligence/AIM-MCP">AIM Guard MCP</a></td>
      <td>로그·행위 데이터 필터링</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>mcp_type</code>, <code>operation_type</code>, <code>sensitivity_level</code>, <code>text</code>, <code>user_prompt</code>, <code>security_level</code> (<code>TEXT JSON</code>)
      </td>
    </tr>
    <tr>
      <td><a href="https://github.com/charles-adedotun/Lilith-Shell">Lilith Shell</a></td>
      <td>웹셸/리버스 쉘 세션 추적 및 공격자 활동 분석</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>TEXT</code>(command, directory)
      </td>
    </tr>
  </tbody>
</table>


## 메모리 포렌식

<table style="table-layout:fixed;width:100%">
  <colgroup>
    <col style="width:20%">
    <col style="width:30%">
    <col style="width:50%">
  </colgroup>
  <thead>
    <tr>
      <th>도구(링크 추가)</th>
      <th>역할</th>
      <th>입력</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><a href="https://github.com/Kirandawadi/volatility3-mcp">Volatility3 MCP (Kirandawadi)</a></td>
      <td>메모리 포렌식 / 프로세스·네트워크 아티팩트 추출</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>.raw</code>, <code>.vmem</code>, <code>.dmp</code>, <code>.mem</code>, <code>.bin</code>, <code>.img</code>, <code>.001</code>, <code>.dump</code>
      </td>
    </tr>
  </tbody>
</table>


## 실행 환경·오케스트레이션

<table style="table-layout:fixed;width:100%">
  <colgroup>
    <col style="width:20%">
    <col style="width:30%">
    <col style="width:50%">
  </colgroup>
  <thead>
    <tr>
      <th>도구(링크 추가)</th>
      <th>역할</th>
      <th>입력</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><a href="https://github.com/kocierik/mcp-nomad">Nomad MCP</a></td>
      <td>MCP 실행·스케줄링·자원 관리 오케스트레이션</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>TEXT</code>(네임스페이스와 경로, 키, 값)
      </td>
    </tr>
  </tbody>
</table>


## IR 운영

<table style="table-layout:fixed;width:100%">
  <colgroup>
    <col style="width:20%">
    <col style="width:30%">
    <col style="width:50%">
  </colgroup>
  <thead>
    <tr>
      <th>도구(링크 추가)</th>
      <th>역할</th>
      <th>입력</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><a href=https://github.com/gbrigandi/mcp-server-thehive">TheHive MCP</a></td>
      <td>IR 대응 및 케이스 관리·협업</td>
      <td style="overflow-wrap:anywhere;vertical-align:top">
        <code>alert_id</code>, <code>case_id</code>, <code>title</code>, <code>description</code>, <code>tags</code>, <code>severity</code>, <code>tlp</code> 등 (<code>TEXT JSON</code>)
      </td>
    </tr>
  </tbody>
</table>

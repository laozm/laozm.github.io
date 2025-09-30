# Windows认证结构详解

## 一、身份验证基础概念

### 1.1 身份验证定义
身份验证是指系统验证用户的登录信息时所使用的过程。用户的名称和密码与授权列表进行比较，如果系统检测到匹配项，则将访问权限授予该用户的权限列表中指定的范围。

### 1.2 Windows默认认证组件
Windows操作系统实现一组默认身份验证安全支持提供程序(SSP)，其中包括：
- Negotiate
- Kerberos协议  
- NTLM
- Schannel（安全通道）
- Digest（摘要）认证实现方式

## 二、核心认证组件架构

### 2.1 本地安全机构（LSA）
**功能职责**：
- 用户身份验证和登录到本地计算机
- 维护有关计算机上的本地安全所有方面的信息（这些方面统称为本地安全策略）
- 提供用于在名称和安全标识符（SID）之间进行转换的各种服务
- 管理本地安全策略、管理审计策略和设置
- 为用户生成包含SID和组权限关系的令牌

**验证流程**：LSA通过访问本地SAM（Security Accounts Manager）数据库，可以完成本地用户的验证。

### 2.2 安全支持提供程序（SSP）架构
**SSPI接口**：安全支持提供程序接口

**SSP定义**：简单的理解为SSP就是一个DLL，来实现身份验证等安全功能，实现的身份验证机制不同

**主要SSP类型**：
- **NTLM SSP** - Challenge/Response验证机制
- **Kerberos SSP** - 基于ticket的身份验证机制  
- **Negotiate SSP** - 协商安全支持提供程序
- **Schannel SSP** - 安全通道
- **Digest SSP** - 摘要式安全支持提供程序
- **CredSSP** - 凭据安全支持提供程序

## 三、主要认证协议详解

### 3.1 NTLM认证协议
**协议基础**：
- NTLM安全支持提供程序（NTLM SSP）是安全支持提供程序接口（SSPI）使用的一种二进制消息传递协议
- 可用于实现NTLM质询-响应身份验证以及协商完整性和机密性选项
- NTLM SSP包括NTLM和NTLM版本2（NTLMv2）身份验证协议

**应用场景**：
- 客户端/服务器身份验证
- 打印服务
- 使用CIFS（SMB）进行文件访问
- 安全远程过程调用服务或DCOM服务
- 位置：`%windir%\Windows\System32\msv1_0.dll`

**认证三阶段**：
1. **协商阶段**：主要用于确认双方协议版本
2. **质询阶段**：就是挑战（Chalenge）/响应（Response）认证机制运行流程（重点）
3. **验证阶段**：验证主要是在质询完成后，验证结果，是认证的最后一步

**质询详细流程**：
1. 客户端向服务器端发送用户信息（用户名）请求
2. 服务器接受到请求，生成一个16位的随机数，被称之为"Challenge"，使用登录用户名对应的NTLM Hash加密Challenge（16位随机字符），生成Challenge1。同时，生成Challenge1后，将Challenge（16位随机字符）发送给客户端
3. 客户端接受到Challenge后，使用将要登录到账户对应的NTLM Hash加密Challenge生成Response，然后将Response发送至服务器端
4. 验证：服务器端收到客户端的Response后，比对Challenge1与Response是否相等，若相等，则认证通过

**注意事项**：
- Challenge是Server产生的一个16字节的随机数，每次认证都不同
- Response的表现形式是Net-NTLM Hash，它是由客户端提供的密码Hash加密Server返回的Challenge产生的结果
- 经过NTLM Hash加密Challenge的结果在网络协议中称之为Net NTLM Hash

**NTLM v2协议改进**：
- Challenge差异：NTLM v1的Challenge有8位，NTLM v2的Challenge为16位
- 加密算法：NTLM v1的主要加密算法是DES，NTLM v2的主要加密算法是HMAC-MD5

### 3.2 Kerberos域认证
**协议特点**：
- 是Windows活动目录中使用的客户/服务器认证协议（windows中的认证协议有两种NTLM和Kerberos）
- 为通信双方提供双向身份认证
- 一种网络认证协议，其设计目标是通过密钥系统为客户机/服务器应用程序提供强大的认证服务

**域认证参与角色**（三只狗头）：
1. **Client** - 客户端
2. **Server** - 服务器
3. **KDC（Key Distribution Center）** = **DC（Domain Controller）** - 域控制器

**基础概念**：
- **票据（Ticket）**：是网络对象互相访问的凭证
- **TGT（Ticket Granting Ticket）**：入场券，通过入场券能够获得票据，是一种临时凭证的存在
- **KDC组成**：
  - **AS（Authentication Service）**：为client生成TGT的服务
  - **TGS（Ticket Granting Service）**：为client生成某个服务的ticket
- **AD（account database）**：存储所有client的白名单，只有存在于白名单的client才能顺利申请到TGT

**域认证粗略流程**：
1. client向kerberos服务请求，希望获取访问server的权限。kerberos得到了这个消息，首先得判断client是否是可信赖的，也就是白名单黑名单的说法。这就是AS服务完成的工作，通过在AD中存储黑名单和白名单来区分client。成功后，返回AS返回TGT给client
2. client得到了TGT后，继续向kerberos请求，希望获取访问server的权限。kerberos又得到了这个消息，这时候通过client消息中的TGT，判断出了client拥有了这个权限，给了client访问server的权限ticket
3. client得到ticket后，终于可以成功访问server。这个ticket只是针对这个server，其他server需要向TGS申请

**详细认证流程**：

**第一步：客户端通过AS获取TGT**
1. 首先客户端要向AS证明自己就是自己。客户端发送自己的用户名和经过自己NTLM加密过的信息（一个暗号）给AS；AS接收到明文用户名后去AD数据库查询对应的NTLM密码，然后解密得到暗号；自此可以证明客户端就是客户端
2. AS成功认证客户端后会生成一个session key，然后将TGT及用客户端派生密码加密的session key返回给客户端；TGT包含（包含一个session key，和该用户信息）TGT用krbtgt的派生秘钥加密；因为是用krbtgt派生秘钥加密的所以客户端无法解密TGT，自此客户端可以得到TGT及session key；客户端会在本地缓存TGT及session key

**第二步：向TGS申请ST**
1. 客户端首先要证明自己就是自己；客户端向TGS发送自己的用户名、TGT、然后用session key加密的暗语、服务名称
2. TGS拿到信息后由于不知道客户端是谁，那么首先用krbtgt派生秘钥解密TGT，得到用户名和session key，然后用session key解密暗语，自此验证客户端发送的信息
3. TGS完成认证之后会首先生成一个service session key然后利用该值生成一个ST（包含客户端信息，和service session key），整个ST是用过要访问的服务器的ntlm加密的，最终是TGS将用session key加密的service session key和用服务端ntlm加密的ST（客户端信息及service session key）返回给客户端
4. 客户端拿到信息后利用缓存的session key解密service session key，然后将service session key及ST缓存

**第三步：向目标服务器发起请求**
1. 客户端要访问服务端资源只需要把ST及用service session key加密的暗号发送给服务端；服务端如何验证ST的真实性呢？因为生成ST的时候是用服务端的派生密码加密的，所有服务端可以解密ST，得到客户端信息及service session key利用service session key解密得到暗号；自此服务端验证客户端的真实性

## 四、其他重要认证组件

### 4.1 终端服务相关
- **TSPKG** - Terminal Services Package身份验证提供程序
- **TSSSP** - Terminal Services SSP终端服务SSP
- **CredSSP** - 配置远程登陆RDP，当选中"Network Layer Authentication"（NLA是网络级身份验证）选项时，它允许在打开图形会话之前进行身份验证
- **RDP SSO功能**依赖于允许"凭据委派（Credential Delegation）"的CredSSP/TSSSP/TSPKG组件

### 4.2 专用认证协议
- **Schannel** - 安全通道（Schannel）用于基于web的服务器身份验证，例如，当用户尝试访问安全web服务器时
- **WDigest** - Digest与NTLM类似也是一种挑战认证的协议，用于轻型目录访问协议（LDAP）和web身份验证（IIS）。摘要式身份验证通过网络以MD5哈希或消息摘要形式传输凭据
- **PKU2U** - Windows 7和Windows Server 2008 R2中引入了PKU2U协议，并将其作为SSP实现。此SSP启用对等身份验证，特别是在Windows 7中引入了名为"家庭组"的媒体和文件共享功能。此功能允许在非域成员的计算机之间共享
- **Negotiate（SPNEGO）** - 简单且受保护的GSS-API协商机制（SPNEGO）构成协商SSP的基础，可用于协商特定身份验证协议。当应用程序调用SSPI登录到网络时，它可以指定SSP来处理请求。如果应用程序指定Negotiate SSP，则它会分析请求，并根据客户配置的安全策略选择相应的提供程序来处理请求
- **Exchange认证**

## 五、本地认证机制

### 5.1 本地认证基础
**密码存储位置**：`%SystemRoot%\system32\config\sam`

**认证基本流程**：
当我们登录系统的时候，系统会自动地读取SAM文件中的"密码"与我们输入的"密码"进行比对，如果相同，证明认证成功！

**重要概念**：
- Windows本身不保存明文密码，只保留密码的Hash
- 为了保证存储的不是明文，从而采用Hash，但是密码Hash也需要特定的生成算法以及表现形式
- 这个SAM文件中保留了计算机本地所有用户的凭证信息，可以理解为是一个数据库

**NTLM Hash与NTLM关系**：
- NTLM是一种网络认证协议，它是基于挑战（Chalenge）/响应（Response）认证机制的一种认证模式。这个协议只支持Windows
- NTLM Hash：就是认证使用到的凭证，这个凭证是经过散列算法生成的，称为NTLM Hash
- NTLM Hash与NTLM的关系：NTLM网络认证协议是以NTLM Hash作为根本凭证进行认证的协议。在本地认证的过程中，其实就是将用户输入的密码转换为NTLM Hash与SAM中的NTLM Hash进行比较

### 5.2 NTLM Hash生成
**生成算法**：
假设我的密码是admin，那么操作系统会将admin转换为十六进制，经过Unicode转换后，再调用MD4加密算法加密，这个加密结果的十六进制就是NTLM Hash

**本地认证详细流程**：
首先，用户注销、重启、锁屏后，操作系统会让winlogon显示登录界面，也就是输入框，接收输入后，将密码交给lsass进程，这个进程中会存一份明文密码，将明文密码加密成NTLM Hash，对SAM数据库比较认证

**LM Hash（历史背景）**：
- 在NTLM协议问世之前，它的前身就是LM（LAN Manager）协议
- LM与NTLM协议的认证机制相同，但是加密算法不同
- 目前大多数的Windows都采用NTLM协议认证，LM协议已经基本淘汰了

## 六、网络认证机制

### 6.1 网络认证场景
假设A主机与B主机属于同一个工作组环境，A想访问B主机上的资料，需要将一个存在于B主机上的账户凭证发送至B主机，经过认证才能够访问B主机上的资源。

这是我们接触比较多的SMB共享文件的案例，SMB的默认端口是445。

### 6.2 认证协议演进
早期SMB协议在网络上传输明文口令。后来出现LAN Manager Challenge/Response验证机制，简称LM，它是如此简单以至很容易就被破解，现在又有了NTLM以及Kerberos。

## 七、安全威胁与防护

### 7.1 哈希传递（Pass The Hash）
**攻击原理**：
哈希传递是能够在不需要账户明文密码的情况下完成认证的一个技术。解决了渗透中获取不到明文密码、破解不了NTLM Hash而又想扩大战果的问题。

**攻击条件**：
1. 哈希传递需要被认证的主机能够访问到服务器
2. 哈希传递需要被传递认证的用户名
3. 哈希传递需要被传递认证用户的NTLM Hash

**攻击性质**：
Pass The Hash能够完成一个不需要输入密码的NTLM协议认证流程，所以不算是一个漏洞，算是一个技巧。

**防护措施**：
1. 禁止NTLM认证
2. 防止NTLM Hash被获取到

### 7.2 票据攻击

#### 白银票据（Silver Tickets）
**攻击特点**：
1. 不需要与KDC进行交互
2. 需要目标服务的NTLM Hash

**攻击原理**：
在第三步认证中的Ticket的组成：Ticket=Server Hash（Server Session Key+Client info+End Time）
当拥有Server Hash时，我们就可以伪造一个不经过KDC认证的一个Ticket。
PS：Server Session Key在未发送Ticket之前，服务器是不知道Server Session Key是什么的。所以，一切凭据都来源于Server Hash。

**伪造步骤**：首先需要导出Server Hash

**防护措施**：
1. 尽量保证服务器凭证不被窃取
2. 开启PAC（Privileged Attribute Certificate）特权属性证书保护功能，PAC主要是规定服务器将票据发送给kerberos服务，由kerberos服务验证票据是否有效

#### 黄金票据（Golden Tickets）
**攻击特点**：
1. 需要与DC通信
2. 需要krbtgt用户的hash
PS：这里的krbtgt hash就是之前讲的KDC Hash

**伪造步骤**：伪造票据

**防护措施**：
从攻击面来看，获取krbtgt用户的hash后，可以在域中进行持久性的隐藏，并且日志无法溯源，但是需要拿到DC权限，使用黄金票据能够在一个域环境中长时间控制整个域。

从防御角度来看，需要经常更新krbtgt的密码，才能够使得原有的票据失效。最根本的办法是不允许域管账户登录其他服务器。

**票据攻击总结**：
白银票据：从攻击面来看，伪造白银票据的难度比伪造黄金票据的难度较小，因为一个域中的服务器如果对外的话，非常容易被入侵，并且容易被转储Server。

从防御角度来看，需要开启PAC认证，但这会降低认证效率，增加DC的负担，最根本的还是要加固服务器本身对外的服务。

## 八、Active Directory域服务

### 8.1 认识域（Active Directory）
域（Active Directory）Windows提供了为企业管理资产、服务、网络对象进行组织化的管理工具。

活动目录服务以域名来划分域的边界，域外就不属于管理范围了，也就是说，一个域对应一个域名，域之间也可以相互信任。

### 8.2 Active Directory（活动目录）功能
1. **服务器及客户端计算机管理**：管理服务器及客户端计算机账户，所有服务器及客户端计算机加入域管理并实施组策略
2. **用户服务**：管理用户域账户、用户信息、企业通讯录（与电子邮件系统集成）、用户组管理、用户身份认证、用户授权管理等，按省实施组管理策略
3. **资源管理**：管理打印机、文件共享服务等网络资源
4. **桌面配置**：系统管理员可以集中的配置各种桌面配置策略，如：用户使用域中资源权限限制、界面功能的限制、应用程序执行特征限制、网络连接限制、安全配置限制等
5. **应用系统支撑**：支持财务、人事、电子邮件、企业信息门户、办公自动化、补丁管理、防病毒系统等各种应用系统

### 8.3 物理架构
从物理层面看，AD与KDC均为域控制器（Domain Controller）

## 九、总结

Windows认证体系采用分层架构设计，通过LSA统一管理多种认证协议，支持从本地认证到域环境的复杂认证需求。理解NTLM和Kerberos等协议的工作原理、认证流程以及相关的安全威胁和防护措施，对于构建安全的Windows网络环境和进行有效的安全防护具有重要意义。

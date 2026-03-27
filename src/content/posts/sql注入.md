---
title: 从面试角度看SQL注入
published: 2026-03-26
updated: 2026-03-26
description: '从面试角度看SQL注入（内含部分大厂面经）（待更新）'
image: ''
tags: [Web Security, SQL Injection, Interview]
category: 'Security'
draft: false
---

⚠️ **重要声明**：以下内容仅用于**网络安全教育、授权渗透测试及安全防御研究**。未经授权对他人系统进行测试或攻击属于违法行为。请严格遵守《中华人民共和国网络安全法》及相关法律法规。发生任何事情与博主无关。

## 一、SQL 注入的原理

### 1. 核心概念
SQL 注入发生的根本原因是：**应用程序没有将“代码（SQL 指令）”与“数据（用户输入）”严格分离。**

当后端代码在构造 SQL 语句时，直接将用户输入的数据拼接到 SQL 字符串中，如果用户输入的内容包含特殊的 SQL 关键字或符号，数据库就会将其误认为是 SQL 命令的一部分执行，从而改变了原有的查询逻辑。

### 2. 工作流程
1.  **用户输入**：攻击者在输入框（如登录名、搜索框、URL 参数）中提交恶意数据。
2.  **代码拼接**：后端程序未做处理，直接将输入拼接到 SQL 语句中。
3.  **数据库执行**：数据库解析并执行了被篡改的 SQL 语句。
4.  **结果返回**：攻击者获取敏感数据、绕过验证或破坏数据库。

### 3. 经典案例展示（登录绕过）
假设后端代码（伪代码）如下：
```sql
SELECT * FROM users WHERE username = '$username' AND password = '$password'
```
**正常情况：**
用户输入 `admin` 和 `123456`，SQL 变为：
```sql
SELECT * FROM users WHERE username = 'admin' AND password = '123456'
```

**注入攻击：**
用户在用户名字段输入：`admin' OR '1'='1`
密码随意输入。拼接后的 SQL 变为：
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = '...'
```
**原理分析：**
由于 `'1'='1'` 恒为真，整个 `WHERE` 条件恒为真。数据库会返回 `users` 表中的第一条记录（通常是管理员），攻击者无需密码即可登录。



## 二、SQL 注入的危害

1.  **数据泄露**：窃取用户信息、密码、商业数据等。
2.  **数据篡改**：修改、删除数据库中的数据（如删库）。
3.  **权限提升**：在某些配置不当的数据库中，可获取操作系统权限（如通过 `LOAD_FILE` 或 `INTO OUTFILE`）。
4.  **网站篡改**：修改网页内容。
5.  **拒绝服务**：执行耗时操作导致数据库瘫痪。



## 三、防御方案

防御 SQL 注入的核心原则是：**永远不要信任用户的输入**，并确保**代码与数据分离**。

### 1. 使用预编译语句（Prepared Statements）【最推荐】
这是防御 SQL 注入**最有效、最根本**的方法。
*   **原理**：SQL 语句的结构先发送给数据库进行编译，用户输入的数据随后作为参数传递。数据库会将参数严格视为“数据”，即使包含 SQL 关键字也不会被执行。
*   **适用**：几乎所有现代编程语言和数据库驱动都支持。

**代码示例：**

*   **Java (JDBC):**
    ```java
    // ❌ 错误做法：字符串拼接
    // String sql = "SELECT * FROM users WHERE name = '" + userName + "'";

    // ✅ 正确做法：预编译
    String sql = "SELECT * FROM users WHERE name = ?";
    PreparedStatement pstmt = connection.prepareStatement(sql);
    pstmt.setString(1, userName); // 参数绑定
    ResultSet rs = pstmt.executeQuery();
    ```

*   **Python (PyMySQL/DB-API):**
    ```python
    # ❌ 错误做法
    # sql = "SELECT * FROM users WHERE name = '%s'" % user_name

    # ✅ 正确做法：使用占位符
    sql = "SELECT * FROM users WHERE name = %s"
    cursor.execute(sql, (user_name,))
    ```

*   **PHP (PDO):**
    ```php
    // ✅ 正确做法
    $stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email');
    $stmt->execute(['email' => $email]);
    ```

### 2. 使用 ORM 框架（对象关系映射）
现代开发框架（如 Hibernate, JPA, MyBatis, Django ORM, Entity Framework）通常内置了防注入机制。
*   **注意**：即使使用 ORM，如果使用了原生 SQL 拼接功能，依然可能注入。
*   **MyBatis 特别警示**：
    *   `#{}`：会使用预编译，**安全**（推荐）。
    *   `${}`：是直接字符串替换，**不安全**（严禁用于用户输入）。
    ```xml
    <!-- ✅ 安全 -->
    SELECT * FROM users WHERE id = #{id}
    <!-- ❌ 危险 -->
    SELECT * FROM users WHERE id = ${id}
    ```

### 3. 输入验证（白名单机制）
对所有用户输入进行严格校验。
*   **类型检查**：确保数字参数确实是整数。
*   **白名单**：对于排序字段（`ORDER BY`）、表名等无法使用预编译的地方，必须使用白名单匹配。
    ```java
    // 排序字段防御
    String[] allowedColumns = {"id", "name", "create_time"};
    if (!Arrays.asList(allowedColumns).contains(sortColumn)) {
        throw new SecurityException("Invalid sort column");
    }
    ```

### 4. 最小权限原则（Least Privilege）
*   数据库连接账号不应使用 `root` 或 `sa` 等高权限账号。
*   仅授予应用程序所需的最低权限（如只给 `SELECT`, `INSERT`, `UPDATE`，禁止 `DROP`, `FILE` 等权限）。
*   这样即使发生注入，攻击者能造成的破坏也有限。

### 5. 关闭错误回显
*   生产环境禁止将详细的数据库错误信息（如 SQL 语法错误、表结构）直接返回给前端。
*   错误信息会暴露数据库类型、表名等关键信息，辅助攻击者进行注入。
*   应统一使用自定义的错误页面。

### 6. 部署 WAF（Web 应用防火墙）
*   在应用层之前部署 WAF，可以拦截常见的 SQL 注入特征流量。
*   **注意**：WAF 是辅助手段，不能作为唯一的防御措施（可能存在绕过）。

> Q：**使用 ORM 一定能够防御 SQL 注入吗，有没有使用了 ORM 但是仍然存在 SQL 注入的可能？（源自字节跳动安全开发一面）**
> A：**使用 ORM（对象关系映射）框架并不能 100% 保证防御 SQL 注入。**
> 虽然 ORM 框架的设计初衷之一就是通过参数化查询来减少 SQL 注入风险，但如果开发人员使用不当或滥用特定功能，依然会导致 SQL 注入漏洞。
> **核心原因**：ORM 只是工具，它提供了安全的方法（如预编译），但也提供了灵活的方法（如原生 SQL、字符串拼接）。安全性取决于开发人员如何调用这些方法。
> 一、为什么用了 ORM 还会注入？（常见场景）
> 1. 使用原生 SQL（Raw SQL）且未参数化
> 大多数 ORM 都允许执行原生 SQL 语句。如果开发者在原生 SQL 中直接拼接用户输入，就绕过了 ORM 的安全机制。
> *   **❌ 危险代码 (Python SQLAlchemy):**
>     ```python
>     # 用户输入直接拼接到字符串中
>     user_input = request.args.get('name')
>     # 即使使用了 ORM 的 session，这里也是字符串拼接
>     sql = "SELECT * FROM users WHERE name = '" + user_input + "'"
>     session.execute(sql) 
>     ```
> *   **✅ 安全代码:**
>     ```python
>     # 使用参数化
>     sql = "SELECT * FROM users WHERE name = :name"
>     session.execute(sql, {"name": user_input})
>     ```
> 2. MyBatis 中的 `${}` 与 `#{}` 混淆
> 这是 Java 开发中最经典的 ORM 注入案例。MyBatis 提供了两种占位符：
> *   `#{}`：预编译处理（安全），会将内容视为字符串参数。
> *   `${}`：字符串直接替换（**危险**），直接将内容拼接到 SQL 中。
> *   **❌ 危险代码 (XML 配置):**
>     ```xml
>     <!-- ${} 会直接替换，如果 id 是 "1 OR 1=1"，SQL 就被篡改了 -->
>     <select id="getUser" resultType="User">
>         SELECT * FROM users WHERE id = ${id}
>     </select>
>     ```
> *   **✅ 安全代码:**
>     ```xml
>     <!-- #{} 会使用预编译 -->
>     <select id="getUser" resultType="User">
>         SELECT * FROM users WHERE id = #{id}
>     </select>
>     ```
> 3. 动态排序（ORDER BY）无法参数化
> SQL 语法规定，**表名、列名、排序方向（ASC/DESC）不能作为预编译的参数**。因此，ORM 在处理动态排序时，往往不得不进行字符串拼接。
> *   **❌ 危险场景:**
>     用户控制排序字段 `sort=createTime` 或 `sort=id; DROP TABLE users--`。
>     ```python
>     # Django ORM 示例
>     sort_field = request.GET.get('sort') 
>     # 如果直接传入用户输入，可能触发注入
>     User.objects.all().order_by(sort_field) 
>     ```
>     *注：现代 ORM（如 Django）会对 order_by 的字段名做一定校验，但如果配合 `extra()` 或 `raw()` 方法则极易注入。
> *   **✅ 防御方案:** 使用**白名单**校验。
>     ```python
>     allowed_sorts = ['id', 'create_time', 'name']
>     if sort_field not in allowed_sorts:
>         sort_field = 'id' # 默认值
>     User.objects.all().order_by(sort_field)
>     ```
> 4. 动态表名
> 与排序类似，表名也不能参数化。如果业务需要根据用户输入切换表名（如分表策略），直接拼接会导致注入。
> *   **❌ 危险代码:**
>     ```java
>     // Hibernate 原生查询
>     String tableName = userInput; 
>     query = session.createSQLQuery("SELECT * FROM " + tableName); 
>     ```
> *   **✅ 防御方案:** 严格白名单映射，禁止用户直接输入表名。
> 5. 二次注入（Second-Order Injection）
> 数据在存入数据库时是安全的（因为用了 ORM 参数化），但在**取出后再次使用**时，被拼接到新的 SQL 中。
> *   **流程：**
>     1.  攻击者注册用户名：`admin' -- `（存入数据库时被视为普通字符串，安全）。
>     2.  管理员后台查询用户：`SELECT * FROM logs WHERE user = '$stored_username'`。
>     3.  代码将数据库取出的 `stored_username` 直接拼接到新查询中，导致注入。
> *   **原因：** 误以为从数据库取出的数据是“可信的”。
> 6. ORM 框架本身的漏洞或配置错误
> *   **版本过旧**：早期版本的 ORM 框架可能存在已知漏洞。
> *   **配置不当**：例如开启了某些允许执行任意 SQL 的调试功能。
> *   **复杂查询构造器**：某些 ORM 的高级查询构造器（Query Builder）允许传入 raw 表达式，如果未过滤，也会注入。
>     *   *Laravel 示例:* `DB::table('users')->whereRaw('id = ' . $input)` 是危险的。

### 总结对照表

| 措施 | 安全性 | 实施难度 | 说明 |
| :--- | :--- | :--- | :--- |
| **预编译语句 (Prepared Statements)** | ⭐⭐⭐⭐⭐ | 低 | **核心方案**，必须使用 |
| **ORM 框架 (正确使用)** | ⭐⭐⭐⭐⭐ | 低 | 避免在 ORM 中手写拼接 SQL |
| **输入验证 (白名单)** | ⭐⭐⭐⭐ | 中 | 针对无法预编译的场景（如排序） |
| **最小权限原则** | ⭐⭐⭐⭐ | 中 | 减小被攻破后的损失 |
| **转义字符 (Escape)** | ⭐⭐ | 低 | 不推荐，容易遗漏，仅作为最后手段 |
| **WAF** | ⭐⭐⭐ | 低 | 辅助防御，不可完全依赖 |



---

在 SQL 注入攻击或安全测试中，如果后端或 WAF（Web 应用防火墙）过滤了**空格（Space, `%20`）**，攻击者或测试人员通常会利用 SQL 语法的灵活性和解析器的特性来寻找替代方案。

以下是常见的**空格过滤绕过技术原理**及**防御对策**。

### 一、为什么可以绕过？

1.  **SQL 解析器的灵活性**：数据库（如 MySQL、MSSQL、Oracle）在解析 SQL 语句时，不仅识别空格作为分隔符，还识别其他空白字符（如制表符、换行符）。
2.  **注释符的特性**：SQL 注释符（如 `/**/`）在解析时会被忽略，但在某些上下文中可以起到分隔关键字的作用。
3.  **WAF 的正则缺陷**：许多 WAF 使用正则表达式匹配特征（如 `UNION SELECT`），如果正则写得不严谨（例如只匹配空格），就容易被绕过。



### 二、常见的空格绕过方法

#### 1. 使用注释符 `/**/` 替代空格
这是最常用的方法。在 MySQL 等数据库中，`/**/` 被视为注释，但在关键字之间可以起到分隔作用。
*   **原始语句**：`UNION SELECT 1, 2, 3`
*   **绕过语句**：`UNION/**/SELECT/**/1,2,3`
*   **原理**：数据库解析时会忽略注释，将其视为 `UNION SELECT 1,2,3` 执行。

#### 2. 使用其他空白字符
除了普通空格（ASCII 32），SQL 解析器通常还接受以下字符作为分隔符：
*   **制表符 (Tab)**：URL 编码为 `%09`
*   **换行符 (New Line)**：URL 编码为 `%0a`
*   **回车符 (Carriage Return)**：URL 编码为 `%0d`
*   **示例**：`UNION%09SELECT%0a1,2,3`

#### 3. 使用括号 `()`
在某些数据库（特别是 MySQL）中，括号可以替代空格来分隔关键字或函数参数。
*   **函数调用**：`SELECT database()` 不需要空格。
*   **子查询**：`UNION(SELECT 1)` 有时可以替代 `UNION SELECT 1`。
*   **示例**：`id=1 AND (1=1)` 替代 `id=1 AND 1=1`。

#### 4. URL 编码与双重编码
如果 WAF 解码一次，而后端解码两次，可以利用编码绕过。
*   **普通空格**：`%20`
*   **双重编码**：`%2520`（`%25` 是 `%` 的编码）。
    *   WAF 看到 `%2520` 可能不认为是空格，放行。
    *   后端第一次解码变成 `%20`，第二次解码变成空格，最终执行。
*   **非标准编码**：某些数据库接受 `%00` (空字节) 或其他特殊编码作为分隔符（取决于具体环境和驱动）。

#### 5. 利用特定数据库语法特性
不同数据库对语法的宽容度不同：
*   **MySQL**：支持 `/**/`，支持 `()` 包裹。
*   **MSSQL**：支持 `;` 分隔语句，有时可用 `/*` 注释。
*   **Oracle**：支持 `/* */`，但对换行符处理较严格。

#### 6. 大小写混合（配合空格绕过）
虽然主要针对关键字过滤，但常与空格绕过结合使用，以混淆 WAF 正则。
*   **示例**：`UnIoN/**/SeLeCT`



### 三、实战示例（模拟场景）

假设存在注入点：`http://example.com/product.php?id=1`
WAF 拦截了包含空格和 `UNION SELECT` 的请求。

**尝试绕过：**
1.  **注释符**：`id=1' UNION/**/SELECT/**/null,null,null--`
2.  **Tab 符**：`id=1' UNION%09SELECT%09null,null,null--`
3.  **括号**：`id=1' AND (SELECT 1)=(SELECT 1)--` (盲注场景)



### 四、如何防御此类绕过？（核心重点）

作为防御者，了解绕过方法是为了更好地配置防御策略。**单纯依赖过滤（黑名单）是永远无法完全防御 SQL 注入的。**

#### 1. 根本防御：预编译语句（Prepared Statements）
*   **原理**：无论攻击者输入什么字符（空格、注释、特殊符号），预编译都将输入视为**纯数据**，而不是 SQL 代码的一部分。
*   **效果**：即使攻击者绕过了空格过滤，输入的内容也不会改变 SQL 结构。
*   **结论**：**这是唯一能彻底解决 SQL 注入（包括所有绕过技巧）的方法。**

#### 2. WAF 策略优化
如果必须使用 WAF 进行防护，不能仅依赖简单的正则：
*   **语义分析**：高级 WAF 会尝试解析 SQL 语义，而不仅仅是匹配字符串。
*   **解码规范化**：在匹配前，对 URL 进行多次解码（防止双重编码绕过），并将所有空白字符（Tab、换行等）统一规范化为空格后再匹配。
*   **更新规则**：及时更新 WAF 规则库，覆盖 `/**/`、`%09` 等常见绕过特征。

#### 3. 最小权限原则
*   数据库账号不应拥有 `UNION`、`LOAD_FILE`、`INTO OUTFILE` 等高危权限。即使注入成功，也无法利用这些语法窃取数据或写文件。

#### 4. 关闭错误回显
*   禁止将数据库错误信息直接展示给用户。这能增加攻击者判断注入是否成功的难度（增加盲注成本）。

#### 总结

| 绕过手段 | 防御核心 |
| :--- | :--- |
| **注释符 `/**/`** | **预编译语句**（彻底免疫） |
| **空白符 `%09`, `%0a`** | **WAF 规范化解码** + 预编译 |
| **括号 `()`** | **预编译语句** |
| **URL 双重编码** | **WAF 多次解码** + 预编译 |

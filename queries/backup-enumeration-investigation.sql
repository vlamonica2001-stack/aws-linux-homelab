-- Log Analysis Investigation: Backup File Enumeration Attack
-- Investigated access_logs on the server after spotting a sudden traffic spike.

-- 1. Profile traffic by user agent
SELECT user_agent, COUNT(*) AS hits
FROM access_logs
GROUP BY user_agent
ORDER BY hits DESC
LIMIT 10;
-- Result: a single generic Chrome user agent accounted for 257 of 336 requests (76%),
-- unlike the legitimate crawlers in the same dataset, which self-identified via a +https:// URL.

-- 2. Isolate the source IP behind that user agent
SELECT ip_address, COUNT(*) AS hits
FROM access_logs
WHERE user_agent LIKE '%Chrome/123.0.0.0%'
GROUP BY ip_address
ORDER BY hits DESC;
-- Result: all 257 requests came from a single IP address.

-- 3. Determine intent: what was actually being requested?
SELECT request_path, COUNT(*) AS hits
FROM access_logs
WHERE ip_address = '190.102.106.158'
GROUP BY request_path
ORDER BY hits DESC
LIMIT 15;
-- Result: every request targeted a different .zip filename (e.g. customer-data.zip,
-- database_export.zip) -> a backup file enumeration attack.

-- 4. Timing analysis: human or automated?
SELECT MIN(request_time), MAX(request_time), COUNT(*)
FROM access_logs
WHERE ip_address = '190.102.106.158';
-- Result: all 257 requests occurred within the same second -> confirms automated tooling.

-- 5. Confirm the outcome
SELECT status_code, COUNT(*)
FROM access_logs
WHERE ip_address = '190.102.106.158'
GROUP BY status_code;
-- Result: all 257 requests returned 404 -> nothing was exposed.

-- 6. Check for a wider campaign
SELECT ip_address, COUNT(*)
FROM access_logs
WHERE request_path LIKE '%.zip'
GROUP BY ip_address;
-- Result: only this one IP attempted .zip requests -> an isolated, single-actor burst.

-- 7. Analyse the wordlist structure behind the attempts
SELECT request_path
FROM access_logs
WHERE ip_address = '190.102.106.158'
AND (request_path LIKE '%sql%' OR request_path LIKE '%data%' OR

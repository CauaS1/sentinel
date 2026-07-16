from scapy.all import *
from datetime import datetime
from configuration import jsonConfig #it's the JSON configuration
import mariadb
import log
import firewall

conn = mariadb.connect(
    user="root",
    password="1234567",
    database="soc_lab" # try deleting this line to see if i can create a logic to check the exitence of this db
)   

cursor = conn.cursor() # Tool that talks to the database

def table_exists():
    # Checks if the network_events database exits
    cursor.execute("""
        SELECT EXISTS ( \
        SELECT 1 FROM INFORMATION_SCHEMA.TABLES \
        WHERE TABLE_SCHEMA = 'soc_lab' AND TABLE_NAME = 'network_events' \
        ) AS table_exists
    """)

    networkEventsDB = cursor.fetchall()
    networkEventsDB = networkEventsDB[0][0]

    if networkEventsDB == 0:
        cursor.execute("""CREATE TABLE network_events ( \
        packet INT AUTO_INCREMENT PRIMARY KEY, \
        timestamp VARCHAR(40),
        src_mac VARCHAR(20),
        dst_mac VARCHAR(20), 
        src_ip VARCHAR(15),
        dst_ip VARCHAR(15),
        src_port VARCHAR(5),
        dst_port VARCHAR(5),
        protocol VARCHAR(8)) 
    """)
        
    # Checks if the triggered_alerts database exits
    cursor.execute("""
        SELECT EXISTS (
            SELECT 1 FROM INFORMATION_SCHEMA.TABLES 
            WHERE TABLE_SCHEMA = 'soc_lab' AND TABLE_NAME = 'triggered_alerts' 
            ) AS table_exists
    """) 

    triggeredAlertDB = cursor.fetchall()
    triggeredAlertDB = triggeredAlertDB[0][0]

    if triggeredAlertDB == 0:
        cursor.execute("""CREATE TABLE triggered_alerts (
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        description VARCHAR(50),
        source_ip VARCHAR(20) UNIQUE,
        request_ammount INT)  
    """)
        
    # Checks if the blacklist_ip database exits
    cursor.execute("""
        SELECT EXISTS (
            SELECT 1 FROM INFORMATION_SCHEMA.TABLES 
            WHERE TABLE_SCHEMA = 'soc_lab' AND TABLE_NAME = 'blacklist_ip' 
            ) AS table_exists
    """) 

    blacklistDB = cursor.fetchall()
    blacklistDB = blacklistDB[0][0]

    if blacklistDB == 0:
        cursor.execute("""CREATE TABLE blacklist_ip (
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        description VARCHAR(80),
        source_ip VARCHAR(20) UNIQUE )
    """)
        
    # Checks if the whitelist database exitis
    cursor.execute("""
        SELECT EXISTS (
            SELECT 1 FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA = 'soc_lab' AND TABLE_NAME = 'whitelist'
            ) AS table_exists
    """)

    whitelist = cursor.fetchall()
    whitelist  = whitelist[0][0]
        
    if whitelist == 0:
        cursor.execute("""CREATE TABLE whitelist ( \
        id INT AUTO_INCREMENT PRIMARY KEY, 
        src_ip VARCHAR(20),
        description VARCHAR(50) )
    """)
        
def snifferFunction():
    # Sniffing the enp0s3 interface for IP packets, storing is true
    packets = sniff(iface=jsonConfig["database"]["interface"], filter="ip", store=True, count=jsonConfig["database"]["count"]) 
    protocol = ''

    # Fixing the timestamp from the response
    fixedTime = datetime.fromtimestamp(packets[1].time)

    le = len(packets)
    print(le)

    for p in packets:

        # Converting the number related to the protocol to its formal name
        protoNum = p[IP].proto

        if protoNum == 1:
            protocol = 'ICMP'
        elif protoNum == 6:
            protocol = 'TCP'
        elif protoNum == 17:
            protocol = 'TCP'

        timestp = str(fixedTime)
        src_mac = str(p[Ether].src)
        dst_mac = str(p[Ether].dst)
        src_ip = str(p[IP].src)
        dst_ip = str(p[IP].dst)
        protoc = str(protocol)
        
        try:
            dst_port = str(p[TCP].dport)
            src_port = str(p[TCP].sport)
        except IndexError:
            dst_port = "None"
            src_port = "None"

        log.eventLogger(src_mac, dst_mac, src_ip, dst_ip, protoc, level="info")

        # Inserting data into the database
            # You can use F-STRING to make the database unsafe for SQL Injection
        cursor.execute("""
        INSERT INTO network_events
        (timestamp, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (timestp, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protoc)
        )

        conn.commit() # Don't forget to commit the changes into the db


def floodPacketsAlert():
    cursor.execute("""
    SELECT timestamp, src_ip from network_events
    """)

    val = cursor.fetchall()

    # Create a disctionary containing the IP and its packet timestamp 
    ipTimes = {}
    for timestamp, ip in val: 
        
        if ip not in ipTimes:
            ipTimes[ip] = []

        ipTimes[ip].append(timestamp)

    cursor.execute(
        "SELECT src_ip FROM network_events" 
    )

    srcIpsFromDB = set(cursor.fetchall())


    IpTimesSortedByHour = {}
    # { '1.1.1.1: { 3: 5 }} | means 5 packets were requests from IP 1.1.1.1 in the HOUR 3

    for s in srcIpsFromDB: # It will navigate throught the list of unique IPS and access the dictionary 
        tmList = ipTimes[s[0]] # the DIC contains the timestamp related to the IP, but it does not show the IP

        ip = s[0]

        if ip not in IpTimesSortedByHour:
            IpTimesSortedByHour[ip] = {} 


        for t in tmList: # it will go through each timestap of the corresponding list [tm1, tm2, tm3...]
            t1 = datetime.strptime(
                t,
                '%Y-%m-%d %H:%M:%S.%f'
            )

            timeByHour = t1.hour # Takes only the hour of each timestamp

            if timeByHour not in IpTimesSortedByHour[ip]:
                IpTimesSortedByHour[ip][timeByHour] = 0

            IpTimesSortedByHour[ip][timeByHour] += 1

    # Doing the alert script -----------------------------

    # Inserting the alerts inside the DB | FLOOD PACKET TYPE
    for ip in srcIpsFromDB:
        for req in IpTimesSortedByHour[ip[0]].values(): # req stands for request ammount
            if req > 5: 
                cursor.execute("""INSERT INTO triggered_alerts
                    (description, source_ip, request_ammount)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                    request_ammount = VALUES (request_ammount)
                    """,
                    ('Packet Flood',ip[0], req ))
                
                    # On duplicated IP, just update the REQUEST_AMOUNT

                conn.commit()
        
def blacklistAdd():
    cursor.execute("SELECT * FROM triggered_alerts")

    alerts = cursor.fetchall() # Get all the data from triggered_alerts database

    # Returned the triggered-source-ip that are the same in both tables
    cursor.execute("""
        SELECT triggered_alerts.source_ip FROM triggered_alerts 
        INNER JOIN blacklist_ip
        ON triggered_alerts.source_ip = blacklist_ip.source_ip 
    """)

    values = cursor.fetchall()

    blackList = []
    for v in values:
        blackList.append(v[0])

    for a in alerts:
        ip = a[2] # The IP
        req = a[3] # Request ammount
        

        if ip not in blackList and req > jsonConfig["blackListThreshold"]:
            log.eventLogger(0, 0, ip, 0, 0, level="critical")
            description = f'{ip} made {req} requests within an hour'

            cursor.execute("""
                INSERT INTO blacklist_ip
                (description, source_ip)
                VALUES (%s, %s)
            """, (description, ip))

            conn.commit()

            firewall.firewallFunc(ip, 'deny', 'in')

def whitelist():
    
    cursor.execute("""
    SELECT * FROM whitelist
    """)

    allowedIps = cursor.fetchall()

    for a in allowedIps:
        print(a[1], a[2])

        firewall.firewallFunc(a[1], "allow", "out")

def artificialData():
    i = 0
    while (i < 6):
        cursor.execute("""
            INSERT INTO network_events
            (timestamp, src_mac, dst_mac, src_ip, dst_ip, protocol)
                VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (f'2026-06-21 14:14:{i}.430358', '11:22:27:61:6c:f9', '08:00:27:61:6c:f9', "192.168.1.15", "0.0.0..1", "TEST")
            )

        conn.commit() # Don't forget to commit the changes into

        i = i + 1
    


table_exists()
blacklistAdd()
snifferFunction()
whitelist()
#artificialData()
floodPacketsAlert()

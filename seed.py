from datetime import date,timedelta
import os, mysql.connector
from dotenv import load_dotenv
import sys
sys.path.insert(0,'.')
from app import hpw
load_dotenv();cfg=dict(host=os.getenv('DB_HOST','127.0.0.1'),port=int(os.getenv('DB_PORT','3306')),database=os.getenv('DB_NAME','relief_board'),user=os.getenv('DB_USER','root'),password=os.getenv('DB_PASSWORD',''))
c=mysql.connector.connect(**cfg);q=c.cursor(dictionary=True)
for t in ['audit_logs','deliveries','dispatches','allocations','requests','resources','users']:q.execute('DELETE FROM '+t)
c.commit()
users=[('Operations Coordinator','coordinator@relief.local','coordinator'),('Resource Manager','manager@relief.local','resource_manager'),('Dispatch Lead','dispatcher@relief.local','dispatcher'),('Demo Viewer','viewer@relief.local','viewer')]
for n,e,r in users:q.execute('INSERT INTO users(name,email,password_hash,role) VALUES(%s,%s,%s,%s)',(n,e,hpw('demo123'),r))
q.execute('SELECT id,email FROM users');uids={x['email']:x['id'] for x in q.fetchall()};uid=uids['coordinator@relief.local']
rs=[('supply','Oxygen Stock #A17','Medical',75,'A',4),('supply','Oxygen Stock #B09','Medical',60,'B',20),('supply','Water Bottles W01','Water',300,'A',90),('supply','Water Bottles W02','Water',250,'C',60),('supply','Emergency Food F11','Food',180,'B',25),('supply','Expiring Medical Kit M23','Medical',50,'C',2),('supply','Expired Medical Kit X1','Medical',40,'A',-2),('supply','Water Bottles W03','Water',200,'B',30),('vehicle','Ambulance-07','Medical Transport',1,'B',None),('vehicle','Relief Truck-12','Transport',3,'A',None),('vehicle','Water Tanker-03','Water Transport',2,'C',None),('volunteer','Medical Team Alpha','First Aid',6,'A',None),('volunteer','Shelter Team Delta','Shelter',8,'D',None),('shelter','Temporary Shelter 1','Shelter',200,'C',None),('shelter','Temporary Shelter 2','Shelter',120,'A',None),('supply','Expired Water Batch Z9','Water',100,'D',-1),('supply','Medical Kit M40','Medical',90,'B',18)]
for typ,n,cap,qty,z,days in rs:q.execute("INSERT INTO resources(resource_type,name,capability,total_qty,available_qty,location_zone,expiry_date,status) VALUES(%s,%s,%s,%s,%s,%s,%s,'available')",(typ,n,cap,qty,qty,z,(date.today()+timedelta(days=days) if days is not None else None)))
reqs=[('medical oxygen','Medical',100,'A','CRITICAL',95),('water','Water',500,'A','CRITICAL',90),('medical kit','Medical',120,'C','HIGH',80),('ambulance','Medical Transport',1,'A','CRITICAL',100),('transport','Transport',2,'D','HIGH',85),('first aid','First Aid',5,'A','HIGH',80),('shelter','Shelter',150,'C','HIGH',75),('water','Water',150,'D','MEDIUM',55),('food','Food',100,'B','HIGH',70),('blanket','Shelter',70,'D','MEDIUM',50),('medical oxygen','Medical',40,'B','MEDIUM',45),('water','Water',80,'C','LOW',30),('medical kit','Medical',30,'D','MEDIUM',60),('first aid','First Aid',12,'C','HIGH',88),('water','Water',1000,'D','CRITICAL',98),('shelter','Shelter',50,'A','LOW',20)]
for rt,cap,qty,z,p,u in reqs:q.execute('INSERT INTO requests(request_type,required_capability,required_qty,location_zone,priority,urgency,created_by) VALUES(%s,%s,%s,%s,%s,%s,%s)',(rt,cap,qty,z,p,u,uid))
c.commit();q.close();c.close();print('Seeded. Password for all demo users: demo123')

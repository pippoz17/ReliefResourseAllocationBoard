import os,mysql.connector
from pathlib import Path
from dotenv import load_dotenv
load_dotenv();c=mysql.connector.connect(host=os.getenv('DB_HOST','127.0.0.1'),port=int(os.getenv('DB_PORT','3306')),database=os.getenv('DB_NAME','relief_board'),user=os.getenv('DB_USER','root'),password=os.getenv('DB_PASSWORD',''));cur=c.cursor()
for s in Path('schema.sql').read_text().split(';'):
    if s.strip():cur.execute(s)
c.commit();cur.close();c.close();print('Schema ready')

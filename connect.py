import pymysql
import sys
import os


def create_database_and_tables():
    try:
        # Get database password from environment variable, default to '123456'
        db_password = os.getenv('DB_PASSWORD', '123456')

        # Initial connection to MySQL server without specifying a database
        connection = pymysql.connect(
            host='localhost',
            user='root',
            password=db_password
        )
        print("成功连接到MySQL服务器")

        cursor = connection.cursor()
        # Create databases if they don’t exist
        cursor.execute("CREATE DATABASE IF NOT EXISTS dbtest CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        cursor.execute("CREATE DATABASE IF NOT EXISTS daily_data CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        print("数据库 dbtest 和 daily_data 创建成功或已存在")

        connection.close()

        # Connect to dbtest database
        connection = pymysql.connect(
            host='localhost',
            user='root',
            password=db_password,
            database='dbtest'
        )
        cursor = connection.cursor()

        # Create users table (no email, compatible with bcrypt)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(100) NOT NULL
        ) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
        """)

        # Create physicians table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS physicians (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(100) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
        """)

        # Create user_profile table with user_id as primary key
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_profile (
            user_id INT PRIMARY KEY,
            username VARCHAR(50),
            gender ENUM('男', '女', '其他'),
            age INT,
            phone VARCHAR(20),
            address TEXT,
            birth_date DATE,
            emergency_contact VARCHAR(100),
            emergency_phone VARCHAR(20),
            health_conditions TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
        """)

        # Create medical_records table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS medical_records (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            file_name VARCHAR(255) NOT NULL,
            file_type VARCHAR(50),
            file_data BLOB,
            upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
        """)

        # Create emergency_events table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS emergency_events (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            emergency_contact VARCHAR(100),
            emergency_phone VARCHAR(20),
            event_type VARCHAR(100),
            event_time DATETIME,
            event_description TEXT,
            past_medical_history TEXT,
            current_condition TEXT,
            medication_or_equipment TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
        """)

        # Create health_consultations table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS health_consultations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            physician_id INT,
            question TEXT NOT NULL,
            answer TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            answered_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (physician_id) REFERENCES physicians(id) ON DELETE SET NULL
        ) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
        """)

        # 在 create_database_and_tables() 函数中，添加以下代码（在其他表创建之后）
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS family_members (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            name VARCHAR(50) NOT NULL,
            relationship VARCHAR(50) NOT NULL,
            phone VARCHAR(20),
            address TEXT,
            birth_date DATE,
            health_conditions TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
        """)

        connection.commit()
        print("数据库和表结构创建完成")

    except pymysql.Error as e:
        print(f"发生错误: {e}")
        sys.exit(1)

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()
            print("数据库连接已关闭")


def verify_tables():
    try:
        db_password = os.getenv('DB_PASSWORD', '123456')
        connection = pymysql.connect(
            host='localhost',
            user='root',
            password=db_password,
            database='dbtest'
        )
        cursor = connection.cursor()
        for table in ['users', 'physicians', 'user_profile', 'medical_records', 'emergency_events',
                      'health_consultations']:
            cursor.execute(f"DESCRIBE {table}")
            print(f"{table} 表结构：", cursor.fetchall())
    except pymysql.Error as e:
        print(f"验证错误: {e}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


if __name__ == "__main__":
    print("开始创建数据库和表结构...")
    create_database_and_tables()
    print("\n验证表结构...")
    verify_tables()
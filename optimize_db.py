import sqlite3

DB_NAME = 'hami_motor_coding.db'

def create_index():
    """
    Adds an index to the parent_id column to dramatically speed up child lookups.
    """
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        print("در حال اضافه کردن ایندکس به دیتابیس برای افزایش سرعت...")

        # This is the command that creates the index
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_parent_id ON coding_structure (parent_id)")

        conn.commit()
        print("ایندکس با موفقیت ایجاد شد. سرعت بارگذاری زیرمجموعه‌ها اکنون باید بهینه باشد.")

    except sqlite3.Error as e:
        print(f"یک خطا در دیتابیس رخ داد: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    create_index()